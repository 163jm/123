//! TUIC 服务端入站（QUIC）
//!
//! TUIC v5 协议基于 QUIC，使用 UUID + 密码认证。
//! 每个连接先通过认证包（Command::Authenticate），再处理代理请求。

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};

use tokio::sync::mpsc;
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    config::inbound::TuicInboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
};

pub struct TuicInbound {
    config: TuicInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl TuicInbound {
    pub fn new(
        config: TuicInboundConfig,
        tcp_tx: mpsc::Sender<InboundTcpStream>,
        udp_tx: mpsc::Sender<InboundUdpPacket>,
    ) -> Self {
        Self { config, tcp_tx, udp_tx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr =
            format!("{}:{}", self.config.listen, self.config.listen_port).parse()?;
        let tag = Arc::new(self.config.tag.clone());

        info!(tag = %tag, addr = %bind, "tuic inbound starting");

        #[cfg(feature = "outbound-net")]
        return self.run_quic(bind, tag).await;

        #[cfg(not(feature = "outbound-net"))]
        {
            anyhow::bail!(
                "tuic inbound '{}': requires feature outbound-net (QUIC support)",
                tag
            );
        }
    }

    #[cfg(feature = "outbound-net")]
    async fn run_quic(self, bind: SocketAddr, tag: Arc<String>) -> anyhow::Result<()> {
        use quinn::{Endpoint, ServerConfig};

        let tls_cfg = &self.config.tls;
        anyhow::ensure!(tls_cfg.enabled, "tuic inbound: TLS must be enabled");

        let server_tls = crate::inbound::server_tls::build_server_config(tls_cfg)?;
        let mut server_tls = (*server_tls).clone();
        server_tls.alpn_protocols = vec![b"tuic".to_vec()];
        let server_tls = Arc::new(server_tls);

        let quic_server_tls = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)?;
        let mut quic_cfg = ServerConfig::with_crypto(Arc::new(quic_server_tls));

        // 配置零 RTT（如果启用）
        if self.config.zero_rtt_handshake {
            Arc::get_mut(&mut quic_cfg.transport)
                .map(|t| t.max_idle_timeout(None));
        }

        let endpoint = Endpoint::server(quic_cfg, bind)?;
        info!(tag = %tag, addr = %bind, "tuic inbound: QUIC endpoint ready");

        // 构建用户字典 uuid -> password_hash
        let users: Arc<HashMap<[u8; 16], Vec<u8>>> = Arc::new(
            self.config
                .users
                .iter()
                .filter_map(|u| {
                    let uuid = Uuid::parse_str(&u.uuid).ok()?;
                    let password_hash = hmac_sha256(u.password.as_bytes(), uuid.as_bytes());
                    Some((*uuid.as_bytes(), password_hash))
                })
                .collect(),
        );

        let auth_timeout = std::time::Duration::from_millis(self.config.auth_timeout);

        loop {
            let conn = match endpoint.accept().await {
                Some(c) => c,
                None => break,
            };

            let tcp_tx = self.tcp_tx.clone();
            let udp_tx = self.udp_tx.clone();
            let tag = tag.clone();
            let users = users.clone();

            tokio::spawn(async move {
                let conn = match tokio::time::timeout(auth_timeout, conn).await {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        debug!(err = %e, "tuic inbound: QUIC handshake failed");
                        return;
                    }
                    Err(_) => {
                        debug!("tuic inbound: QUIC handshake timeout");
                        return;
                    }
                };

                let peer = conn.remote_address();
                if let Err(e) = handle_tuic_conn(conn, peer, users, tcp_tx, udp_tx, &tag).await {
                    debug!(peer = %peer, err = %e, "tuic inbound conn error");
                }
            });
        }

        Ok(())
    }
}

#[cfg(feature = "outbound-net")]
async fn handle_tuic_conn(
    conn: quinn::Connection,
    peer: SocketAddr,
    users: Arc<HashMap<[u8; 16], Vec<u8>>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    _udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: &str,
) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;

    // TUIC v5 协议：
    // 认证命令通过单向流发送（uni-directional）
    // 代理命令通过双向流（bi-directional）

    let mut authenticated = false;

    // 等待认证单向流
    let recv_stream = conn.accept_uni().await?;
    let mut recv = recv_stream;

    // 读取认证包：[VERSION 1B][TYPE 1B][UUID 16B][TOKEN 32B]
    let version = recv.read_u8().await?;
    anyhow::ensure!(version == 0x05, "tuic: unsupported version {version}");

    let cmd_type = recv.read_u8().await?;
    // 0x00 = Authenticate
    if cmd_type != 0x00 {
        anyhow::bail!("tuic: expected Authenticate command, got 0x{cmd_type:02x}");
    }

    let mut uuid = [0u8; 16];
    recv.read_exact(&mut uuid).await?;
    let mut token = [0u8; 32];
    recv.read_exact(&mut token).await?;

    // 验证 token = HMAC-SHA256(password, uuid)
    if let Some(expected_token) = users.get(&uuid) {
        if expected_token.as_slice() == token {
            authenticated = true;
        }
    }

    anyhow::ensure!(authenticated, "tuic: authentication failed");
    debug!(peer = %peer, "tuic inbound: authenticated");

    // 处理代理请求
    loop {
        let (send_stream, recv_stream) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => break,
            Err(e) => return Err(e.into()),
        };

        let tcp_tx = tcp_tx.clone();
        let tag = tag.to_string();

        tokio::spawn(async move {
            if let Err(e) =
                handle_tuic_stream(send_stream, recv_stream, peer, tcp_tx, &tag).await
            {
                debug!(peer = %peer, err = %e, "tuic stream error");
            }
        });
    }

    Ok(())
}

#[cfg(feature = "outbound-net")]
async fn handle_tuic_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: &str,
) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;

    // 代理流格式：[VERSION 1B][TYPE 1B][ADDR ...]
    // TYPE 0x01 = Connect (TCP)
    let version = recv.read_u8().await?;
    anyhow::ensure!(version == 0x05, "tuic: stream version mismatch");

    let cmd = recv.read_u8().await?;
    if cmd != 0x01 {
        anyhow::bail!("tuic: unsupported command 0x{cmd:02x}");
    }

    let target = read_tuic_addr(&mut recv).await?;
    debug!(peer = %peer, target = %target, "tuic inbound: accepted");

    let tuic_stream = TuicBiStream { send, recv };
    tcp_tx
        .send(InboundTcpStream {
            stream: crate::inbound::SniffedStream::from_tuic(tuic_stream),
            target,
            inbound_tag: tag.to_string(),
            sniffed_protocol: None,
            sniffed_domain: None,
        })
        .await
        .ok();

    Ok(())
}

#[cfg(feature = "outbound-net")]
async fn read_tuic_addr(recv: &mut quinn::RecvStream) -> anyhow::Result<Target> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tokio::io::AsyncReadExt;

    let atyp = recv.read_u8().await?;
    match atyp {
        0x00 => {
            // IPv4
            let mut ip = [0u8; 4];
            recv.read_exact(&mut ip).await?;
            let port = recv.read_u16().await?;
            Ok(Target::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)))
        }
        0x01 => {
            // Domain
            let dlen = recv.read_u8().await? as usize;
            let mut domain = vec![0u8; dlen];
            recv.read_exact(&mut domain).await?;
            let port = recv.read_u16().await?;
            Ok(Target::Domain(String::from_utf8(domain)?, port))
        }
        0x02 => {
            // IPv6
            let mut ip = [0u8; 16];
            recv.read_exact(&mut ip).await?;
            let port = recv.read_u16().await?;
            Ok(Target::Socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)))
        }
        other => anyhow::bail!("tuic: unknown atyp 0x{other:02x}"),
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// TUIC QUIC 双向流适配器
#[cfg(feature = "outbound-net")]
pub struct TuicBiStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}
