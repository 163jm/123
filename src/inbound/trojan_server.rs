//! Trojan 服务端入站
//!
//! 协议格式：
//! [Password SHA224 hex (56 bytes)][CRLF][SOCKS5-style address][CRLF][Payload]
//! SOCKS5 address: [CMD 1B][ATYP 1B][Addr][Port 2B]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use sha2::{Digest, Sha224};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tracing::{debug, error, info, warn};

use crate::{
    config::inbound::TrojanInboundConfig,
    inbound::{InboundTcpStream, SniffedStream, Target},
};

pub struct TrojanInbound {
    config: TrojanInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
}

impl TrojanInbound {
    pub fn new(config: TrojanInboundConfig, tcp_tx: mpsc::Sender<InboundTcpStream>) -> Self {
        Self { config, tcp_tx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr =
            format!("{}:{}", self.config.listen, self.config.listen_port).parse()?;
        let tag = Arc::new(self.config.tag.clone());

        // 预计算所有用户密码的 SHA224 hex
        let hashed_passwords: Arc<Vec<Vec<u8>>> = Arc::new(
            self.config
                .users
                .iter()
                .map(|u| sha224_hex(u.password.as_bytes()))
                .collect(),
        );

        // 构建 TLS acceptor
        #[cfg(feature = "outbound-net")]
        let tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>> =
            build_tls_acceptor(&self.config)?;
        #[cfg(not(feature = "outbound-net"))]
        if self.config.tls.as_ref().is_some_and(|t| t.enabled) {
            warn!(tag = %tag, "trojan inbound: TLS requested but feature outbound-net is not enabled");
        }

        info!(tag = %tag, addr = %bind, "trojan inbound starting");
        let listener = TcpListener::bind(bind).await?;

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!(err = %e, "trojan inbound accept error");
                    continue;
                }
            };

            let tcp_tx = self.tcp_tx.clone();
            let tag = tag.clone();
            let hashed_passwords = hashed_passwords.clone();

            #[cfg(feature = "outbound-net")]
            let acceptor = tls_acceptor.clone();

            tokio::spawn(async move {
                #[cfg(feature = "outbound-net")]
                let res = handle_conn_tls(stream, peer, hashed_passwords, acceptor, tcp_tx, &tag).await;
                #[cfg(not(feature = "outbound-net"))]
                let res = handle_conn_plain(stream, peer, hashed_passwords, tcp_tx, &tag).await;
                if let Err(e) = res {
                    debug!(peer = %peer, err = %e, "trojan inbound conn error");
                }
            });
        }
    }
}

#[cfg(feature = "outbound-net")]
fn build_tls_acceptor(
    cfg: &TrojanInboundConfig,
) -> anyhow::Result<Option<Arc<tokio_rustls::TlsAcceptor>>> {
    match &cfg.tls {
        Some(tls) if tls.enabled => {
            let acceptor = crate::inbound::server_tls::build_acceptor(tls)?;
            Ok(Some(Arc::new(acceptor)))
        }
        _ => Ok(None),
    }
}

#[cfg(feature = "outbound-net")]
async fn handle_conn_tls(
    stream: TcpStream,
    peer: SocketAddr,
    hashed_passwords: Arc<Vec<Vec<u8>>>,
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: &str,
) -> anyhow::Result<()> {
    if let Some(acceptor) = tls_acceptor {
        let tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|e| anyhow::anyhow!("trojan TLS handshake: {e}"))?;
        process_and_relay_trojan(tls_stream, peer, &hashed_passwords, tcp_tx, tag).await
    } else {
        handle_conn_plain(stream, peer, hashed_passwords, tcp_tx, tag).await
    }
}

async fn handle_conn_plain(
    mut stream: TcpStream,
    peer: SocketAddr,
    hashed_passwords: Arc<Vec<Vec<u8>>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: &str,
) -> anyhow::Result<()> {
    let target = decode_trojan_header(&mut stream, &hashed_passwords).await?;

    debug!(peer = %peer, target = %target, "trojan inbound: accepted (plain)");

    tcp_tx
        .send(InboundTcpStream {
            stream: SniffedStream::new(stream),
            target,
            inbound_tag: tag.to_string(),
            sniffed_protocol: None,
            sniffed_domain: None,
        })
        .await
        .ok();

    Ok(())
}

async fn process_and_relay_trojan<S>(
    mut stream: S,
    peer: SocketAddr,
    hashed_passwords: &[Vec<u8>],
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: &str,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let target = decode_trojan_header(&mut stream, hashed_passwords).await?;
    debug!(peer = %peer, target = %target, "trojan inbound: accepted (TLS), direct relay");

    let target_addr = match &target {
        Target::Domain(host, port) => format!("{host}:{port}"),
        Target::Socket(addr) => addr.to_string(),
    };

    let outbound = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(&target_addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timeout: {target_addr}"))?
    .map_err(|e| anyhow::anyhow!("connect failed: {target_addr}: {e}"))?;

    info!(peer = %peer, target = %target, "trojan inbound: relaying");

    let (mut r1, mut w1) = tokio::io::split(stream);
    let (mut r2, mut w2) = outbound.into_split();
    let up = tokio::io::copy(&mut r1, &mut w2);
    let dn = tokio::io::copy(&mut r2, &mut w1);
    tokio::try_join!(up, dn).ok();

    Ok(())
}

async fn decode_trojan_header<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    hashed_passwords: &[Vec<u8>],
) -> anyhow::Result<Target> {
    // 读取 56 字节 SHA224 hex
    let mut password_hex = [0u8; 56];
    stream.read_exact(&mut password_hex).await?;

    // 验证密码
    let authed = hashed_passwords
        .iter()
        .any(|hp| hp.as_slice() == &password_hex);
    anyhow::ensure!(authed, "trojan: unauthorized password");

    // CRLF
    let mut crlf = [0u8; 2];
    stream.read_exact(&mut crlf).await?;
    anyhow::ensure!(crlf == *b"\r\n", "trojan: expected CRLF after password");

    // SOCKS5 地址: [CMD 1B][ATYP 1B][Addr][Port 2B BE][CRLF]
    let cmd = stream.read_u8().await?;
    anyhow::ensure!(cmd == 0x01, "trojan: only TCP CONNECT (0x01) supported");

    let atyp = stream.read_u8().await?;
    let target = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            Target::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        0x03 => {
            let dlen = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; dlen];
            stream.read_exact(&mut domain).await?;
            let port = stream.read_u16().await?;
            Target::Domain(String::from_utf8(domain)?, port)
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            Target::Socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        other => anyhow::bail!("trojan: unknown atyp 0x{other:02x}"),
    };

    // CRLF
    let mut crlf = [0u8; 2];
    stream.read_exact(&mut crlf).await?;
    anyhow::ensure!(crlf == *b"\r\n", "trojan: expected CRLF after address");

    Ok(target)
}

fn sha224_hex(data: &[u8]) -> Vec<u8> {
    let hash = Sha224::digest(data);
    let hex = format!("{hash:x}");
    hex.into_bytes()
}
