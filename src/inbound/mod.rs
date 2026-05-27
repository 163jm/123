//! 入站层：负责接收本机流量，识别目标地址，交给路由层处理。
//!
//! 原有透明代理入站：
//! - [`tproxy`]：Linux TProxy，透明代理，TCP + UDP
//! - [`redir`]：Linux Redirect（NAT），透明代理，仅 TCP
//! - [`mixed`]：SOCKS5 + HTTP CONNECT，TCP + UDP ASSOCIATE
//! - [`dns`]：DNS 服务器入站
//! - [`tun`]：TUN 虚拟网卡，L3 透明代理，TCP + UDP
//!
//! 服务端协议入站（新增）：
//! - [`vless_server`]：VLESS 服务端，TCP/WS/xHTTP + TLS/Reality
//! - [`vmess_server`]：VMess 服务端，TCP/WS + TLS
//! - [`trojan_server`]：Trojan 服务端，TCP/WS + TLS
//! - [`shadowsocks_server`]：Shadowsocks 服务端，AEAD/2022
//! - [`hysteria2_server`]：Hysteria2 服务端，QUIC + TLS
//! - [`tuic_server`]：TUIC 服务端，QUIC + TLS

pub mod dns;
pub mod mixed;
#[cfg(target_os = "linux")]
pub mod redir;
#[cfg(target_os = "linux")]
pub mod tproxy;
pub mod tun;

// ── 服务端协议入站 ────────────────────────────────────────────────────────────
pub mod hysteria2_server;
pub mod shadowsocks_server;
pub mod server_tls;
pub mod trojan_server;
pub mod tuic_server;
pub mod vless_server;
pub mod vmess_server;

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

// ── 共享抽象 ──────────────────────────────────────────────────────────────────

/// 一条已建立的入站 TCP 连接，携带原始目标地址。
/// 路由层拿到它后决定走哪个出站。
pub struct InboundTcpStream {
    /// TCP 流（可能携带嗅探时 peek 出的前缀字节）
    pub stream: SniffedStream,
    /// 连接的真实目标（域名或 IP:Port）
    pub target: Target,
    /// 来自哪个入站 tag
    pub inbound_tag: String,
    /// 嗅探识别出的应用层协议（如 `"dns"`），未嗅探时为 None
    pub sniffed_protocol: Option<String>,
    /// 嗅探识别出的域名（override_destination=false 时不覆盖 target，但保存在此）
    pub sniffed_domain: Option<String>,
}

// ── SniffedStream ─────────────────────────────────────────────────────────────

/// 入站流的统一抽象，支持：
/// 1. 普通 TcpStream（最常见）
/// 2. 泛型 AsyncRead+AsyncWrite（服务端协议入站的 TLS/WS 流）
///
/// 读取顺序：先消耗 `prefix`，再透传内部流。
/// 写入、关闭等操作直接委托给内部流。
pub struct SniffedStream {
    /// 嗅探阶段 peek 出的字节（未嗅探时为空）
    pub prefix: Bytes,
    pub inner: InnerStream,
    /// 实时流量计数器（可选）
    pub live_down: Option<std::sync::Arc<std::sync::atomic::AtomicI64>>,
    pub live_up: Option<std::sync::Arc<std::sync::atomic::AtomicI64>>,
}

/// 内部流类型
pub enum InnerStream {
    /// 裸 TcpStream（大多数情况）
    Tcp(TcpStream),
    /// 泛型流（服务端 TLS/QUIC 协议，已解码协议头后的净荷层）
    Generic(Box<dyn DynStream>),
}

/// 泛型异步流 trait（对象安全）
pub trait DynStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> DynStream for T {}

impl SniffedStream {
    /// 从裸 TcpStream 创建（最常用）
    pub fn new(stream: TcpStream) -> Self {
        Self {
            prefix: Bytes::new(),
            inner: InnerStream::Tcp(stream),
            live_down: None,
            live_up: None,
        }
    }

    /// 从泛型流创建（服务端 TLS/WS 等）
    pub fn from_generic<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(stream: S) -> Self {
        Self {
            prefix: Bytes::new(),
            inner: InnerStream::Generic(Box::new(stream)),
            live_down: None,
            live_up: None,
        }
    }

    /// 从 Hysteria2 QUIC 双向流创建
    #[cfg(feature = "outbound-net")]
    pub fn from_hy2(stream: crate::inbound::hysteria2_server::Hy2BiStream) -> Self {
        Self::from_generic(Hy2DynStream(stream))
    }

    /// 从 TUIC QUIC 双向流创建
    #[cfg(feature = "outbound-net")]
    pub fn from_tuic(stream: crate::inbound::tuic_server::TuicBiStream) -> Self {
        Self::from_generic(TuicDynStream(stream))
    }

    /// 注入实时计数器
    pub fn set_live_counters(
        &mut self,
        live_up: std::sync::Arc<std::sync::atomic::AtomicI64>,
        live_down: std::sync::Arc<std::sync::atomic::AtomicI64>,
    ) {
        self.live_up = Some(live_up);
        self.live_down = Some(live_down);
    }

    /// 嗅探完成后，将 peek 出的字节作为 prefix 归还
    pub fn prepend(&mut self, data: Bytes) {
        if data.is_empty() {
            return;
        }
        if self.prefix.is_empty() {
            self.prefix = data;
        } else {
            let mut buf = bytes::BytesMut::with_capacity(self.prefix.len() + data.len());
            buf.extend_from_slice(&self.prefix);
            buf.extend_from_slice(&data);
            self.prefix = buf.freeze();
        }
    }

    /// 尝试获取底层 TcpStream 的对端地址
    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        match &self.inner {
            InnerStream::Tcp(s) => s.peer_addr(),
            InnerStream::Generic(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "peer_addr not available for non-TCP streams",
            )),
        }
    }
}

impl AsyncRead for SniffedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let amt = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..amt]);
            self.prefix.advance(amt);
            if let Some(c) = &self.live_down {
                c.fetch_add(amt as i64, std::sync::atomic::Ordering::Relaxed);
            }
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let result = match &mut self.inner {
            InnerStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            InnerStream::Generic(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        };
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                if let Some(c) = &self.live_down {
                    c.fetch_add(n as i64, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        result
    }
}

impl AsyncWrite for SniffedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = match &mut self.inner {
            InnerStream::Tcp(s) => Pin::new(s).poll_write(cx, data),
            InnerStream::Generic(s) => Pin::new(s.as_mut()).poll_write(cx, data),
        };
        if let Poll::Ready(Ok(n)) = &result {
            if let Some(c) = &self.live_up {
                c.fetch_add(*n as i64, std::sync::atomic::Ordering::Relaxed);
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            InnerStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            InnerStream::Generic(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            InnerStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            InnerStream::Generic(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

// ── Hysteria2 / TUIC QUIC 流适配器 ────────────────────────────────────────────

#[cfg(feature = "outbound-net")]
struct Hy2DynStream(crate::inbound::hysteria2_server::Hy2BiStream);

#[cfg(feature = "outbound-net")]
impl AsyncRead for Hy2DynStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0.recv).poll_read(cx, buf)
    }
}

#[cfg(feature = "outbound-net")]
impl AsyncWrite for Hy2DynStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0.send).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0.send).poll_shutdown(cx)
    }
}

#[cfg(feature = "outbound-net")]
struct TuicDynStream(crate::inbound::tuic_server::TuicBiStream);

#[cfg(feature = "outbound-net")]
impl AsyncRead for TuicDynStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0.recv).poll_read(cx, buf)
    }
}

#[cfg(feature = "outbound-net")]
impl AsyncWrite for TuicDynStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0.send).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0.send).poll_shutdown(cx)
    }
}

// ── InboundUdpPacket 等其余类型（保持不变）────────────────────────────────────

/// 一个入站 UDP 数据包（或 UDP 会话的第一个包），携带原始目标地址。
pub struct InboundUdpPacket {
    pub data: bytes::Bytes,
    pub src: SocketAddr,
    pub target: Target,
    pub inbound_tag: String,
    pub sniffed_protocol: Option<String>,
    pub sniffed_domain: Option<String>,
    pub session: UdpSession,
    pub upstream_rx: Option<tokio::sync::mpsc::Receiver<bytes::Bytes>>,
    pub lifetime_guards: Vec<Box<dyn std::any::Any + Send>>,
}

/// 连接目标：域名或 IP
#[derive(Debug, Clone)]
pub enum Target {
    Domain(String, u16),
    Socket(SocketAddr),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Self::Domain(_, p) => *p,
            Self::Socket(a) => a.port(),
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Domain(d, _) => d.clone(),
            Self::Socket(a) => a.ip().to_string(),
        }
    }

    pub fn to_socket_addr_lossy(&self) -> SocketAddr {
        match self {
            Self::Socket(a) => *a,
            Self::Domain(_, p) => SocketAddr::from(([0, 0, 0, 0], *p)),
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(d, p) => write!(f, "{d}:{p}"),
            Self::Socket(a) => write!(f, "{a}"),
        }
    }
}

/// UDP 会话句柄
#[derive(Debug, Clone)]
pub struct UdpSession {
    pub reply_tx: tokio::sync::mpsc::Sender<(bytes::Bytes, SocketAddr, SocketAddr)>,
}
