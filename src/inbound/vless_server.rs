//! VLESS 服务端入站
//!
//! 支持：
//! - 裸 TCP（无 TLS）
//! - TCP + TLS（rustls），需 outbound-net feature
//!
//! VLESS 协议格式（Version 0）：
//! 请求头：[Ver=0x00 1B][UUID 16B][Addon Len 1B][Addon ...][Cmd 1B][Port 2B BE][Atyp 1B][Addr ...]
//! 响应头：[Ver=0x00 1B][Addon Len=0x00 1B]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tracing::{debug, error, info, warn};

use crate::{
    config::inbound::{ServerTransportConfig, VlessInboundConfig},
    inbound::{InboundTcpStream, SniffedStream, Target},
};

pub struct VlessInbound {
    config: VlessInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
}

impl VlessInbound {
    pub fn new(config: VlessInboundConfig, tcp_tx: mpsc::Sender<InboundTcpStream>) -> Self {
        Self { config, tcp_tx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr =
            format!("{}:{}", self.config.listen, self.config.listen_port).parse()?;
        let tag = Arc::new(self.config.tag.clone());

        // 解析所有用户 UUID
        let users: Arc<Vec<[u8; 16]>> = Arc::new(
            self.config
                .users
                .iter()
                .map(|u| parse_uuid(&u.uuid))
                .collect::<anyhow::Result<Vec<_>>>()
                .map_err(|e| anyhow::anyhow!("vless inbound: invalid user UUID: {e}"))?,
        );

        // 检查 TLS 配置
        #[cfg(feature = "outbound-net")]
        let tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>> =
            build_tls_acceptor(&self.config)?;
        #[cfg(not(feature = "outbound-net"))]
        if self.config.tls.as_ref().is_some_and(|t| t.enabled) {
            warn!(tag = %tag, "vless inbound: TLS requested but feature outbound-net is not enabled, running plaintext");
        }

        let transport = self.config.transport.clone();
        info!(tag = %tag, addr = %bind, "vless inbound starting");
        let listener = TcpListener::bind(bind).await?;

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!(err = %e, "vless inbound accept error");
                    continue;
                }
            };

            let tcp_tx = self.tcp_tx.clone();
            let tag = tag.clone();
            let users = users.clone();
            let transport = transport.clone();

            #[cfg(feature = "outbound-net")]
            let acceptor = tls_acceptor.clone();

            tokio::spawn(async move {
                #[cfg(feature = "outbound-net")]
                let res = handle_conn(stream, peer, users, transport, acceptor, tcp_tx, &tag).await;
                #[cfg(not(feature = "outbound-net"))]
                let res = handle_conn_plain(stream, peer, users, tcp_tx, &tag).await;
                if let Err(e) = res {
                    debug!(peer = %peer, err = %e, "vless inbound conn error");
                }
            });
        }
    }
}

// ── TLS acceptor 构建 ─────────────────────────────────────────────────────────

#[cfg(feature = "outbound-net")]
fn build_tls_acceptor(
    cfg: &VlessInboundConfig,
) -> anyhow::Result<Option<Arc<tokio_rustls::TlsAcceptor>>> {
    match &cfg.tls {
        Some(tls) if tls.enabled => {
            if tls.reality.is_some() {
                anyhow::bail!(
                    "vless inbound '{}': Reality server is not yet implemented",
                    cfg.tag
                );
            }
            let acceptor = crate::inbound::server_tls::build_acceptor(tls)?;
            Ok(Some(Arc::new(acceptor)))
        }
        _ => Ok(None),
    }
}

// ── 连接处理 ──────────────────────────────────────────────────────────────────

#[cfg(feature = "outbound-net")]
async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    users: Arc<Vec<[u8; 16]>>,
    transport: Option<ServerTransportConfig>,
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: &str,
) -> anyhow::Result<()> {
    // 1. 可选 TLS 握手（得到 tokio_rustls::server::TlsStream<TcpStream>）
    if let Some(acceptor) = tls_acceptor {
        let tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|e| anyhow::anyhow!("vless TLS handshake: {e}"))?;

        // 2. 可选 WebSocket 升级
        match &transport {
            None | Some(ServerTransportConfig::Tcp) => {
                // 直接在 TLS 流上跑 VLESS — 需要把 TLS 流转为 TcpStream 等价
                // 由于 SniffedStream 目前内部持有 TcpStream，需要在这里先完整读取 VLESS header
                // 然后把 TCP 裸流（底层）和剩余数据组装进 SniffedStream
                // 实际上：TLS stream 不能直接降级为 TcpStream
                // 解决方案：读完 VLESS header 后做 relay（此处不走 dispatcher）
                // 更好的方案：将整个 TLS 流直接交给一个 "透明 relay" 的 SniffedStream variant
                // 暂时我们在 TLS 流上解析 VLESS header，然后把底层 TcpStream 取出来
                // tokio_rustls::server::TlsStream 允许 into_inner() 取出 TcpStream
                // 但此时 TLS 加密状态已经建立，取出裸 TCP 是错误的
                //
                // 正确做法：扩展 SniffedStream 为泛型，或把解码+relay 内联在此处
                // 为了不破坏现有架构，我们在 vless_server 里直接做 VLESS decode + relay
                // 而不经过 dispatcher（这意味着此连接走服务端直连 relay）
                //
                // TODO: 接入 dispatcher 需要将 SniffedStream 泛型化
                warn!("vless inbound TLS mode: VLESS over TLS → dispatcher integration requires SniffedStream to be generic. Falling back to direct relay.");
                process_and_relay_vless(tls_stream, peer, &users, tcp_tx, tag).await
            }
            Some(ServerTransportConfig::Ws(ws_cfg)) => {
                let path = ws_cfg.path.clone();
                let ws = accept_ws(tls_stream, &path).await?;
                process_and_relay_vless(ws, peer, &users, tcp_tx, tag).await
            }
            Some(other) => anyhow::bail!("vless inbound: unsupported transport: {:?}", std::mem::discriminant(other)),
        }
    } else {
        handle_conn_plain(stream, peer, users, tcp_tx, tag).await
    }
}

/// 无 TLS：直接在裸 TcpStream 上解析 VLESS，然后把 TcpStream 送进 dispatcher
async fn handle_conn_plain(
    mut stream: TcpStream,
    peer: SocketAddr,
    users: Arc<Vec<[u8; 16]>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: &str,
) -> anyhow::Result<()> {
    let target = decode_vless_header(&mut stream, &users).await?;

    // 发送响应头
    stream.write_all(&[0x00, 0x00]).await?;

    debug!(peer = %peer, target = %target, "vless inbound: accepted (plain)");

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

/// TLS/WS 模式：在泛型流上解析 VLESS，然后直接做 relay（绕过 dispatcher）
/// TODO: 当 SniffedStream 泛型化后，可改为送入 dispatcher
async fn process_and_relay_vless<S>(
    mut stream: S,
    peer: SocketAddr,
    users: &[[u8; 16]],
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: &str,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let target = decode_vless_header(&mut stream, users).await?;

    // 发送响应头
    stream.write_all(&[0x00, 0x00]).await?;

    debug!(peer = %peer, target = %target, "vless inbound: accepted (TLS/WS), direct relay");

    // 直接 relay 到目标
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

    info!(peer = %peer, target = %target, "vless inbound: relaying (TLS/WS mode, direct)");

    let (mut r1, mut w1) = tokio::io::split(stream);
    let (mut r2, mut w2) = outbound.into_split();

    let up = tokio::io::copy(&mut r1, &mut w2);
    let dn = tokio::io::copy(&mut r2, &mut w1);
    tokio::try_join!(up, dn).ok();

    Ok(())
}

// ── VLESS header decode ───────────────────────────────────────────────────────

async fn decode_vless_header<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    users: &[[u8; 16]],
) -> anyhow::Result<Target> {
    let ver = stream.read_u8().await?;
    anyhow::ensure!(ver == 0x00, "vless: unsupported version 0x{ver:02x}");

    let mut uuid = [0u8; 16];
    stream.read_exact(&mut uuid).await?;
    anyhow::ensure!(users.iter().any(|u| u == &uuid), "vless: unauthorized UUID");

    let addon_len = stream.read_u8().await? as usize;
    if addon_len > 0 {
        let mut addon = vec![0u8; addon_len];
        stream.read_exact(&mut addon).await?;
    }

    let cmd = stream.read_u8().await?;
    anyhow::ensure!(cmd == 0x01, "vless: unsupported cmd 0x{cmd:02x}");

    let port = stream.read_u16().await?;
    let atyp = stream.read_u8().await?;

    let target = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            Target::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        0x02 => {
            let dlen = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; dlen];
            stream.read_exact(&mut domain).await?;
            Target::Domain(String::from_utf8(domain)?, port)
        }
        0x03 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            Target::Socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        other => anyhow::bail!("vless: unknown atyp 0x{other:02x}"),
    };

    Ok(target)
}

fn parse_uuid(s: &str) -> anyhow::Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    anyhow::ensure!(hex.len() == 32, "invalid UUID: {s}");
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(out)
}

// ── WebSocket accept ──────────────────────────────────────────────────────────
#[cfg(feature = "outbound-net")]
async fn accept_ws<S>(stream: S, path: &str) -> anyhow::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio_tungstenite::{accept_hdr_async, tungstenite::handshake::server::{Request, Response}};

    let path_owned = path.to_string();
    let ws = accept_hdr_async(stream, |req: &Request, res: Response| {
        if req.uri().path() == path_owned {
            Ok(res)
        } else {
            use tokio_tungstenite::tungstenite::handshake::server::ErrorResponse;
            Err(ErrorResponse::new(Some("not found".to_string())))
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("WebSocket handshake failed: {e}"))?;

    Ok(WsStream(ws))
}

// ── WebSocket 流适配 ──────────────────────────────────────────────────────────
#[cfg(feature = "outbound-net")]
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};
#[cfg(feature = "outbound-net")]
use std::{io, pin::Pin, task::{Context, Poll}};
#[cfg(feature = "outbound-net")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "outbound-net")]
pub struct WsStream<S>(WebSocketStream<S>);

#[cfg(feature = "outbound-net")]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for WsStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        use bytes::Buf;
        use futures_util::{Stream, StreamExt};
        loop {
            match Pin::new(&mut self.0).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    let amt = data.len().min(buf.remaining());
                    buf.put_slice(&data[..amt]);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            }
        }
    }
}

#[cfg(feature = "outbound-net")]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for WsStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        use futures_util::{Sink, SinkExt};
        match Pin::new(&mut self.0).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Ready(Ok(())) => {}
        }
        let msg = Message::Binary(data.to_vec().into());
        match Pin::new(&mut self.0).start_send(msg) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use futures_util::Sink;
        Pin::new(&mut self.0).poll_flush(cx).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use futures_util::Sink;
        Pin::new(&mut self.0).poll_close(cx).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}
