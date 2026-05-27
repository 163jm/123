//! Hysteria2 服务端入站（QUIC）
//!
//! Hysteria2 基于 QUIC，使用密码认证。
//! 服务端接收 QUIC 连接，验证密码后创建 HTTP/3 隧道。
//!
//! 依赖：quinn (QUIC)，需要 outbound-net feature

use std::{net::SocketAddr, sync::Arc};

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
    config::inbound::{Hysteria2InboundConfig, Hysteria2User},
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
};

pub struct Hysteria2Inbound {
    config: Hysteria2InboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl Hysteria2Inbound {
    pub fn new(
        config: Hysteria2InboundConfig,
        tcp_tx: mpsc::Sender<InboundTcpStream>,
        udp_tx: mpsc::Sender<InboundUdpPacket>,
    ) -> Self {
        Self { config, tcp_tx, udp_tx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr =
            format!("{}:{}", self.config.listen, self.config.listen_port).parse()?;
        let tag = Arc::new(self.config.tag.clone());

        info!(tag = %tag, addr = %bind, "hysteria2 inbound starting");

        #[cfg(feature = "outbound-net")]
        return self.run_quic(bind, tag).await;

        #[cfg(not(feature = "outbound-net"))]
        {
            anyhow::bail!(
                "hysteria2 inbound '{}': requires feature outbound-net (QUIC support)",
                tag
            );
        }
    }

    #[cfg(feature = "outbound-net")]
    async fn run_quic(self, bind: SocketAddr, tag: Arc<String>) -> anyhow::Result<()> {
        use quinn::{Endpoint, ServerConfig};

        // 构建 TLS 配置
        let tls_cfg = &self.config.tls;
        anyhow::ensure!(tls_cfg.enabled, "hysteria2 inbound: TLS must be enabled");

        let server_tls = crate::inbound::server_tls::build_server_config(tls_cfg)?;

        // 为 QUIC 调整 ALPN
        let mut server_tls = (*server_tls).clone();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_tls = Arc::new(server_tls);

        let quic_cfg = ServerConfig::with_crypto(server_tls);
        let endpoint = Endpoint::server(quic_cfg, bind)?;

        info!(tag = %tag, addr = %bind, "hysteria2 inbound: QUIC endpoint ready");

        let passwords: Arc<Vec<String>> = Arc::new(
            self.config.users.iter().map(|u| u.password.clone()).collect()
        );

        loop {
            let conn = match endpoint.accept().await {
                Some(c) => c,
                None => break,
            };

            let tcp_tx = self.tcp_tx.clone();
            let udp_tx = self.udp_tx.clone();
            let tag = tag.clone();
            let passwords = passwords.clone();

            tokio::spawn(async move {
                let conn = match conn.await {
                    Ok(c) => c,
                    Err(e) => {
                        debug!(err = %e, "hysteria2 inbound: QUIC connection failed");
                        return;
                    }
                };
                let peer = conn.remote_address();
                if let Err(e) = handle_quic_conn(conn, peer, passwords, tcp_tx, udp_tx, &tag).await {
                    debug!(peer = %peer, err = %e, "hysteria2 inbound conn error");
                }
            });
        }

        Ok(())
    }
}

#[cfg(feature = "outbound-net")]
async fn handle_quic_conn(
    conn: quinn::Connection,
    peer: SocketAddr,
    passwords: Arc<Vec<String>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: &str,
) -> anyhow::Result<()> {
    // Hysteria2 使用 HTTP/3 协议进行认证和代理请求
    // 认证通过 POST /:auth HTTP/3 请求完成
    // 代理通过 CONNECT 或 UDP forwardings 完成
    //
    // 简化实现：接受连接后循环处理双向流
    loop {
        let (send_stream, recv_stream) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => break,
            Err(e) => return Err(e.into()),
        };

        let tcp_tx = tcp_tx.clone();
        let tag = tag.to_string();
        let passwords = passwords.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_hy2_stream(send_stream, recv_stream, peer, passwords, tcp_tx, &tag).await
            {
                debug!(peer = %peer, err = %e, "hysteria2 stream error");
            }
        });
    }
    Ok(())
}

#[cfg(feature = "outbound-net")]
async fn handle_hy2_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
    passwords: Arc<Vec<String>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: &str,
) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;

    // Hysteria2 代理请求格式（QUIC stream）：
    // [Type 1B][ADDR ...][Payload]
    // Type: 0x00 = TCP CONNECT, 0x01 = UDP
    //
    // 地址格式（SOCKS5-like）：
    // [ATYP 1B][Addr][Port 2B]
    //
    // 认证通过在第一个连接的 Auth 流中传递密码。
    // 简化：假设每个 bi-stream 第一个字节是认证令牌长度，然后是令牌，然后是代理请求

    // 读取认证令牌
    let token_len = recv.read_u8().await? as usize;
    let mut token = vec![0u8; token_len];
    recv.read_exact(&mut token).await?;
    let token_str = String::from_utf8_lossy(&token);

    let authed = passwords.iter().any(|p| p == token_str.as_ref());
    if !authed {
        anyhow::bail!("hysteria2: unauthorized password");
    }

    // 读取代理类型
    let proxy_type = recv.read_u8().await?;

    // 读取目标地址
    let target = read_hy2_addr(&mut recv).await?;

    debug!(peer = %peer, target = %target, "hysteria2 inbound: accepted");

    if proxy_type == 0x00 {
        // TCP CONNECT
        let hy2_stream = Hy2BiStream { send, recv };
        tcp_tx
            .send(InboundTcpStream {
                stream: crate::inbound::SniffedStream::from_hy2(hy2_stream),
                target,
                inbound_tag: tag.to_string(),
                sniffed_protocol: None,
                sniffed_domain: None,
            })
            .await
            .ok();
    }

    Ok(())
}

#[cfg(feature = "outbound-net")]
async fn read_hy2_addr(recv: &mut quinn::RecvStream) -> anyhow::Result<Target> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tokio::io::AsyncReadExt;

    let atyp = recv.read_u8().await?;
    match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            recv.read_exact(&mut ip).await?;
            let port = recv.read_u16().await?;
            Ok(Target::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)))
        }
        0x03 => {
            let dlen = recv.read_u8().await? as usize;
            let mut domain = vec![0u8; dlen];
            recv.read_exact(&mut domain).await?;
            let port = recv.read_u16().await?;
            Ok(Target::Domain(String::from_utf8(domain)?, port))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            recv.read_exact(&mut ip).await?;
            let port = recv.read_u16().await?;
            Ok(Target::Socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)))
        }
        other => anyhow::bail!("hysteria2: unknown atyp 0x{other:02x}"),
    }
}

// Hysteria2 QUIC 双向流适配器（供 SniffedStream::from_hy2 使用）
#[cfg(feature = "outbound-net")]
pub struct Hy2BiStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}
