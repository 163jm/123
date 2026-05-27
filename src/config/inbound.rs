use serde::{Deserialize, Serialize};

/// 所有入站类型的枚举，用 `type` 字段做 tag。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InboundConfig {
    /// Linux TProxy，需要外部 iptables/nftables 配合（TCP + UDP）
    TProxy(TProxyInboundConfig),
    /// Linux Redirect（iptables -j REDIRECT / nftables redirect to），仅 TCP
    Redir(RedirInboundConfig),
    /// SOCKS5 + HTTP CONNECT 混合入站
    Mixed(MixedInboundConfig),
    /// DNS 服务器入站（将查询交由内部 DNS 模块处理后返回）
    Dns(DnsInboundConfig),
    /// TUN 虚拟网卡入站（L3 透明代理，TCP + UDP）
    Tun(TunInboundConfig),
    // ── 服务端协议入站 ────────────────────────────────────────────────────────
    /// VLESS 服务端入站（支持 TCP/WS/xHTTP 传输 + TLS/Reality）
    #[serde(rename = "vless")]
    Vless(VlessInboundConfig),
    /// VMess 服务端入站（支持 TCP/WS 传输 + TLS）
    #[serde(rename = "vmess")]
    Vmess(VmessInboundConfig),
    /// Trojan 服务端入站（支持 TCP/WS 传输 + TLS）
    #[serde(rename = "trojan")]
    Trojan(TrojanInboundConfig),
    /// Shadowsocks 服务端入站
    #[serde(rename = "shadowsocks")]
    Shadowsocks(ShadowsocksInboundConfig),
    /// Hysteria2 服务端入站（QUIC）
    #[serde(rename = "hysteria2")]
    Hysteria2(Hysteria2InboundConfig),
    /// TUIC 服务端入站（QUIC）
    #[serde(rename = "tuic")]
    Tuic(TuicInboundConfig),
}

impl InboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::TProxy(c) => &c.tag,
            Self::Redir(c) => &c.tag,
            Self::Mixed(c) => &c.tag,
            Self::Dns(c) => &c.tag,
            Self::Tun(c) => &c.tag,
            Self::Vless(c) => &c.tag,
            Self::Vmess(c) => &c.tag,
            Self::Trojan(c) => &c.tag,
            Self::Shadowsocks(c) => &c.tag,
            Self::Hysteria2(c) => &c.tag,
            Self::Tuic(c) => &c.tag,
        }
    }

    pub fn listen_addr(&self) -> (&str, u16) {
        match self {
            Self::TProxy(c) => (&c.listen, c.listen_port),
            Self::Redir(c) => (&c.listen, c.listen_port),
            Self::Mixed(c) => (&c.listen, c.listen_port),
            Self::Dns(c) => (&c.listen, c.listen_port),
            // TUN 入站无 listen 地址；port=0 在校验中豁免
            Self::Tun(_) => ("", 0),
            Self::Vless(c) => (&c.listen, c.listen_port),
            Self::Vmess(c) => (&c.listen, c.listen_port),
            Self::Trojan(c) => (&c.listen, c.listen_port),
            Self::Shadowsocks(c) => (&c.listen, c.listen_port),
            Self::Hysteria2(c) => (&c.listen, c.listen_port),
            Self::Tuic(c) => (&c.listen, c.listen_port),
        }
    }
}

// ── TProxy ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TProxyInboundConfig {
    pub tag: String,

    /// 监听地址，默认 0.0.0.0
    #[serde(default = "default_listen")]
    pub listen: String,

    pub listen_port: u16,

    /// 支持的网络协议
    #[serde(default)]
    pub network: Network,

    /// SO_MARK，用于 writeback socket 绕过 TProxy 规则，与 global.routing_mark 一致
    #[serde(default)]
    pub routing_mark: u32,
}

// ── Redirect (NAT) ────────────────────────────────────────────────────────────

/// Linux Redirect 入站配置。
///
/// 对应 `iptables -t nat -j REDIRECT` 或 `nftables redirect to` 规则。
/// 仅支持 TCP；UDP 无法通过 REDIRECT 还原原始目标地址。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedirInboundConfig {
    pub tag: String,

    /// 监听地址，默认 0.0.0.0（接收所有被 redirect 过来的连接）
    #[serde(default = "default_listen")]
    pub listen: String,

    /// 监听端口，需与 nftables/iptables 规则中的 redirect 目标端口一致
    pub listen_port: u16,
}

// ── Mixed（SOCKS5 + HTTP CONNECT）────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_local")]
    pub listen: String,

    pub listen_port: u16,

    #[serde(default)]
    pub network: Network,

    /// SOCKS5 用户名（可选，不填则不鉴权）
    #[serde(default)]
    pub username: Option<String>,

    /// SOCKS5 密码
    #[serde(default)]
    pub password: Option<String>,
}

// ── DNS-in ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_local")]
    pub listen: String,

    /// 默认 53
    #[serde(default = "default_dns_port")]
    pub listen_port: u16,

    #[serde(default)]
    pub network: Network,
}

// ── 公共辅助类型 ──────────────────────────────────────────────────────────────

/// 网络协议选择
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// 仅 TCP
    Tcp,
    /// 仅 UDP
    Udp,
    /// TCP + UDP（默认）
    #[default]
    #[serde(alias = "tcp+udp")]
    TcpUdp,
}

impl Network {
    pub fn tcp(&self) -> bool {
        matches!(self, Self::Tcp | Self::TcpUdp)
    }
    pub fn udp(&self) -> bool {
        matches!(self, Self::Udp | Self::TcpUdp)
    }
}

fn default_listen() -> String {
    "0.0.0.0".into()
}
fn default_listen_local() -> String {
    "127.0.0.1".into()
}
fn default_dns_port() -> u16 {
    53
}

// ── TUN ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunInboundConfig {
    pub tag: String,
    #[serde(default)]
    pub interface_name: Option<String>,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u32,
    pub address: Vec<String>,
    #[serde(default)]
    pub auto_route: bool,
    #[serde(default = "default_iproute2_table_index")]
    pub iproute2_table_index: u32,
    #[serde(default = "default_iproute2_rule_index")]
    pub iproute2_rule_index: u32,
    #[serde(default)]
    pub strict_route: bool,
    #[serde(default = "default_tun_stack")]
    pub stack: String,
    #[serde(default)]
    pub include_interface: Vec<String>,
    #[serde(default)]
    pub exclude_interface: Vec<String>,
    #[serde(default)]
    pub include_uid: Vec<u32>,
    #[serde(default)]
    pub exclude_uid: Vec<u32>,
    #[serde(default)]
    pub udp_timeout: u64,
}

fn default_tun_mtu() -> u32 { 9000 }
fn default_tun_stack() -> String { "system".to_string() }
fn default_iproute2_table_index() -> u32 { 2022 }
fn default_iproute2_rule_index() -> u32 { 9000 }

// ═══════════════════════════════════════════════════════════════════════════════
// 服务端协议入站配置（与 sing-box 对齐）
// ═══════════════════════════════════════════════════════════════════════════════

// ── 服务端 TLS 配置 ──────────────────────────────────────────────────────────

/// 服务端 TLS 配置（cert + key + 可选 Reality）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTlsConfig {
    /// 是否启用 TLS
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// 证书路径（PEM 格式）
    #[serde(default)]
    pub certificate_path: Option<String>,

    /// 证书内容（PEM 字符串，与 certificate_path 二选一）
    #[serde(default)]
    pub certificate: Vec<String>,

    /// 私钥路径（PEM 格式）
    #[serde(default)]
    pub key_path: Option<String>,

    /// 私钥内容（PEM 字符串，与 key_path 二选一）
    #[serde(default)]
    pub key: Vec<String>,

    /// SNI（通常与 listen 地址对应的域名）
    #[serde(default)]
    pub server_name: Option<String>,

    /// ALPN 列表
    #[serde(default)]
    pub alpn: Vec<String>,

    /// Reality 服务端配置（存在时启用 Reality）
    #[serde(default)]
    pub reality: Option<RealityServerConfig>,
}

fn default_true() -> bool { true }

/// Reality 服务端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityServerConfig {
    /// 是否启用
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// x25519 私钥（base64url 编码）
    pub private_key: String,

    /// x25519 公钥（base64url 编码，供客户端使用）
    pub public_key: String,

    /// 允许的 shortId 列表（hex，0~16 字符）
    #[serde(default)]
    pub short_ids: Vec<String>,

    /// 回落目标（真实 HTTPS 站，例如 "example.com:443"）
    pub dest: String,

    /// 对外展示的 SNI
    pub server_name: String,

    /// 最大时间误差（秒），默认 60
    #[serde(default = "default_reality_max_time_diff")]
    pub max_time_diff: u64,
}

fn default_reality_max_time_diff() -> u64 { 60 }

// ── V2Ray 传输层（服务端共用）──────────────────────────────────────────────────

/// 服务端传输层配置（与出站 VlessTransportConfig 镜像，类型名不同）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerTransportConfig {
    /// 裸 TCP
    Tcp,
    /// WebSocket
    Ws(WsServerTransportConfig),
    /// xHTTP（XHTTP / splitHTTP）
    Xhttp(XhttpServerTransportConfig),
    /// gRPC
    Grpc(GrpcServerTransportConfig),
    /// HTTPUpgrade
    #[serde(rename = "httpupgrade")]
    HttpUpgrade(HttpUpgradeServerTransportConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WsServerTransportConfig {
    /// WebSocket 路径，默认 "/"
    #[serde(default = "default_ws_path")]
    pub path: String,
    /// 期望的 Host 头（可选，不填则不校验）
    #[serde(default)]
    pub host: Option<String>,
    /// 最大早期数据长度（0 = 禁用）
    #[serde(default)]
    pub max_early_data: u32,
    /// 早期数据 HTTP 头名称
    #[serde(default)]
    pub early_data_header_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct XhttpServerTransportConfig {
    /// xHTTP 路径，默认 "/"
    #[serde(default = "default_ws_path")]
    pub path: String,
    /// 期望的 Host 头（可选）
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GrpcServerTransportConfig {
    /// gRPC 服务名
    #[serde(default)]
    pub service_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpUpgradeServerTransportConfig {
    #[serde(default = "default_ws_path")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
}

fn default_ws_path() -> String { "/".to_string() }

// ── 服务端多路复用配置 ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerMultiplexConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub padding: bool,
}

// ── VLESS 入站 ────────────────────────────────────────────────────────────────

/// VLESS 服务端入站配置（与 sing-box VLESSInboundOptions 对齐）
///
/// 配置示例：
/// ```json
/// {
///   "type": "vless",
///   "tag": "vless-in",
///   "listen": "0.0.0.0",
///   "listen_port": 443,
///   "users": [
///     { "name": "user1", "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "flow": "xtls-rprx-vision" }
///   ],
///   "tls": {
///     "enabled": true,
///     "certificate_path": "/path/to/cert.pem",
///     "key_path": "/path/to/key.pem"
///   },
///   "transport": { "type": "ws", "path": "/ws" }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen")]
    pub listen: String,

    pub listen_port: u16,

    /// 允许连接的用户列表
    #[serde(default)]
    pub users: Vec<VlessUser>,

    /// TLS 配置（含 Reality）
    #[serde(default)]
    pub tls: Option<ServerTlsConfig>,

    /// 传输层配置
    #[serde(default)]
    pub transport: Option<ServerTransportConfig>,

    /// 多路复用
    #[serde(default)]
    pub multiplex: Option<ServerMultiplexConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessUser {
    /// 用户名（仅用于日志标记）
    pub name: String,
    /// UUID
    pub uuid: String,
    /// XTLS flow（"xtls-rprx-vision"），可选
    #[serde(default)]
    pub flow: Option<String>,
}

// ── VMess 入站 ────────────────────────────────────────────────────────────────

/// VMess 服务端入站配置（与 sing-box VMessInboundOptions 对齐）
///
/// 配置示例：
/// ```json
/// {
///   "type": "vmess",
///   "tag": "vmess-in",
///   "listen": "0.0.0.0",
///   "listen_port": 10086,
///   "users": [
///     { "name": "user1", "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "alterId": 0 }
///   ],
///   "transport": { "type": "ws", "path": "/vmess" }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmessInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen")]
    pub listen: String,

    pub listen_port: u16,

    #[serde(default)]
    pub users: Vec<VmessUser>,

    #[serde(default)]
    pub tls: Option<ServerTlsConfig>,

    #[serde(default)]
    pub transport: Option<ServerTransportConfig>,

    #[serde(default)]
    pub multiplex: Option<ServerMultiplexConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmessUser {
    pub name: String,
    pub uuid: String,
    /// alterId，现代 VMess 应设为 0
    #[serde(rename = "alterId", default)]
    pub alter_id: u16,
}

// ── Trojan 入站 ───────────────────────────────────────────────────────────────

/// Trojan 服务端入站配置（与 sing-box TrojanInboundOptions 对齐）
///
/// 配置示例：
/// ```json
/// {
///   "type": "trojan",
///   "tag": "trojan-in",
///   "listen": "0.0.0.0",
///   "listen_port": 443,
///   "users": [{ "name": "user1", "password": "your-password" }],
///   "tls": { "enabled": true, "certificate_path": "/cert.pem", "key_path": "/key.pem" }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrojanInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen")]
    pub listen: String,

    pub listen_port: u16,

    #[serde(default)]
    pub users: Vec<TrojanUser>,

    #[serde(default)]
    pub tls: Option<ServerTlsConfig>,

    #[serde(default)]
    pub transport: Option<ServerTransportConfig>,

    #[serde(default)]
    pub multiplex: Option<ServerMultiplexConfig>,

    /// 回落目标（TLS 握手失败时回落到此地址，例如 nginx）
    #[serde(default)]
    pub fallback: Option<FallbackConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrojanUser {
    pub name: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackConfig {
    pub server: String,
    pub server_port: u16,
}

// ── Shadowsocks 入站 ──────────────────────────────────────────────────────────

/// Shadowsocks 服务端入站配置（与 sing-box ShadowsocksInboundOptions 对齐）
///
/// 支持单用户和多用户模式：
/// - 单用户：设置顶级 `method` + `password`
/// - 多用户：设置 `users` 列表（method 必须是 2022 系列）
///
/// 配置示例（单用户）：
/// ```json
/// {
///   "type": "shadowsocks",
///   "tag": "ss-in",
///   "listen": "0.0.0.0",
///   "listen_port": 8388,
///   "method": "2022-blake3-aes-256-gcm",
///   "password": "base64-encoded-32-byte-key"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen")]
    pub listen: String,

    pub listen_port: u16,

    /// 加密方法（支持 2022-blake3-* 和旧版 aes-128-gcm / chacha20-ietf-poly1305 等）
    pub method: String,

    /// 单用户密码
    #[serde(default)]
    pub password: Option<String>,

    /// 多用户列表（与 sing-box destinations 兼容）
    #[serde(default)]
    pub users: Vec<ShadowsocksUser>,

    /// 网络协议（tcp/udp/tcp+udp）
    #[serde(default)]
    pub network: Network,

    #[serde(default)]
    pub multiplex: Option<ServerMultiplexConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksUser {
    pub name: String,
    pub password: String,
}

// ── Hysteria2 入站 ────────────────────────────────────────────────────────────

/// Hysteria2 服务端入站配置（与 sing-box Hysteria2InboundOptions 对齐）
///
/// Hysteria2 基于 QUIC，必须有 TLS。
///
/// 配置示例：
/// ```json
/// {
///   "type": "hysteria2",
///   "tag": "hy2-in",
///   "listen": "0.0.0.0",
///   "listen_port": 443,
///   "users": [{ "name": "user1", "password": "your-password" }],
///   "tls": { "enabled": true, "certificate_path": "/cert.pem", "key_path": "/key.pem" }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2InboundConfig {
    pub tag: String,

    #[serde(default = "default_listen")]
    pub listen: String,

    pub listen_port: u16,

    #[serde(default)]
    pub users: Vec<Hysteria2User>,

    /// TLS 配置（必须）
    pub tls: ServerTlsConfig,

    /// 服务端上行带宽上限（Mbps），0 = 不限
    #[serde(default)]
    pub up_mbps: u32,

    /// 服务端下行带宽上限（Mbps），0 = 不限
    #[serde(default)]
    pub down_mbps: u32,

    /// 忽略客户端声明的带宽（服务端主导）
    #[serde(default)]
    pub ignore_client_bandwidth: bool,

    /// 混淆配置
    #[serde(default)]
    pub obfs: Option<Hysteria2ObfsConfig>,

    /// 伪装配置（接受非 Hysteria2 请求时展示的内容）
    #[serde(default)]
    pub masquerade: Option<Hysteria2MasqueradeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2User {
    #[serde(default)]
    pub name: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2ObfsConfig {
    /// 混淆类型，目前仅支持 "salamander"
    #[serde(rename = "type")]
    pub obfs_type: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2MasqueradeConfig {
    /// 伪装类型："proxy" 或 "file" 或 "string"
    #[serde(rename = "type")]
    pub masquerade_type: String,
    /// proxy 模式：回落目标 URL
    #[serde(default)]
    pub url: Option<String>,
    /// proxy 模式：是否重写 Host 头
    #[serde(default)]
    pub rewrite_host: bool,
    /// file 模式：静态文件目录
    #[serde(default)]
    pub directory: Option<String>,
    /// string 模式：固定响应内容
    #[serde(default)]
    pub content: Option<String>,
    /// string 模式：HTTP 状态码
    #[serde(default = "default_masquerade_status_code")]
    pub status_code: u16,
}

fn default_masquerade_status_code() -> u16 { 200 }

// ── TUIC 入站 ─────────────────────────────────────────────────────────────────

/// TUIC 服务端入站配置（与 sing-box TUICInboundOptions 对齐）
///
/// TUIC 基于 QUIC，必须有 TLS。
///
/// 配置示例：
/// ```json
/// {
///   "type": "tuic",
///   "tag": "tuic-in",
///   "listen": "0.0.0.0",
///   "listen_port": 443,
///   "users": [{ "name": "user1", "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "password": "pass" }],
///   "tls": { "enabled": true, "certificate_path": "/cert.pem", "key_path": "/key.pem" }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuicInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen")]
    pub listen: String,

    pub listen_port: u16,

    #[serde(default)]
    pub users: Vec<TuicUser>,

    /// TLS 配置（必须）
    pub tls: ServerTlsConfig,

    /// 拥塞控制算法："cubic"（默认）/ "new_reno" / "bbr"
    #[serde(default = "default_congestion_control")]
    pub congestion_control: String,

    /// 认证超时（毫秒），默认 3000
    #[serde(default = "default_tuic_auth_timeout_ms")]
    pub auth_timeout: u64,

    /// 0-RTT 握手
    #[serde(default)]
    pub zero_rtt_handshake: bool,

    /// 心跳间隔（毫秒），0 = 禁用
    #[serde(default = "default_tuic_heartbeat_ms")]
    pub heartbeat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuicUser {
    #[serde(default)]
    pub name: String,
    pub uuid: String,
    #[serde(default)]
    pub password: String,
}

fn default_congestion_control() -> String { "cubic".to_string() }
fn default_tuic_auth_timeout_ms() -> u64 { 3000 }
fn default_tuic_heartbeat_ms() -> u64 { 10000 }

// ── 原有测试保持不变 ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_redir() {
        let v = json!({
            "type": "redir",
            "tag": "redir-in",
            "listen": "0.0.0.0",
            "listen_port": 7892
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ib.tag(), "redir-in");
        assert!(matches!(ib, InboundConfig::Redir(_)));
        let (listen, port) = ib.listen_addr();
        assert_eq!(listen, "0.0.0.0");
        assert_eq!(port, 7892);
    }

    #[test]
    fn parse_redir_defaults() {
        let v = json!({
            "type": "redir",
            "tag": "redir-in",
            "listen_port": 7892
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        let (listen, _) = ib.listen_addr();
        assert_eq!(listen, "0.0.0.0");
    }

    #[test]
    fn parse_tproxy() {
        let v = json!({
            "type": "tproxy",
            "tag": "tp-in",
            "listen": "0.0.0.0",
            "listen_port": 7893,
            "network": "tcp+udp",
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ib.tag(), "tp-in");
        assert!(matches!(ib, InboundConfig::TProxy(_)));
    }

    #[test]
    fn parse_mixed_defaults() {
        let v = json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen_port": 7890
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        let (listen, port) = ib.listen_addr();
        assert_eq!(listen, "127.0.0.1");
        assert_eq!(port, 7890);
        if let InboundConfig::Mixed(c) = &ib {
            assert!(c.network.udp());
        }
    }

    #[test]
    fn parse_dns_in() {
        let v = json!({
            "type": "dns",
            "tag": "dns-in",
            "listen": "0.0.0.0",
            "listen_port": 5353,
            "network": "udp"
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert!(matches!(ib, InboundConfig::Dns(_)));
        if let InboundConfig::Dns(c) = ib {
            assert!(c.network.udp());
            assert!(!c.network.tcp());
        }
    }

    #[test]
    fn network_both() {
        let n: Network = serde_json::from_str("\"tcp+udp\"").unwrap();
        assert!(n.tcp() && n.udp());
    }

    #[test]
    fn parse_tun_minimal() {
        let v = json!({
            "type": "tun",
            "tag": "tun-in",
            "address": ["198.18.0.1/16"]
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ib.tag(), "tun-in");
        assert!(matches!(ib, InboundConfig::Tun(_)));
        if let InboundConfig::Tun(c) = &ib {
            assert_eq!(c.mtu, 9000);
            assert_eq!(c.stack, "system");
            assert!(!c.auto_route);
            assert!(!c.strict_route);
            assert!(c.interface_name.is_none());
        }
    }

    #[test]
    fn parse_vless_inbound() {
        let v = json!({
            "type": "vless",
            "tag": "vless-in",
            "listen": "0.0.0.0",
            "listen_port": 443,
            "users": [
                { "name": "user1", "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" }
            ],
            "tls": {
                "enabled": true,
                "certificate_path": "/etc/ssl/cert.pem",
                "key_path": "/etc/ssl/key.pem"
            },
            "transport": { "type": "ws", "path": "/ws" }
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ib.tag(), "vless-in");
        assert!(matches!(ib, InboundConfig::Vless(_)));
        if let InboundConfig::Vless(c) = &ib {
            assert_eq!(c.users.len(), 1);
            assert_eq!(c.users[0].name, "user1");
            assert!(c.tls.is_some());
        }
    }

    #[test]
    fn parse_vmess_inbound() {
        let v = json!({
            "type": "vmess",
            "tag": "vmess-in",
            "listen": "0.0.0.0",
            "listen_port": 10086,
            "users": [
                { "name": "user1", "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "alterId": 0 }
            ]
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ib.tag(), "vmess-in");
        assert!(matches!(ib, InboundConfig::Vmess(_)));
    }

    #[test]
    fn parse_trojan_inbound() {
        let v = json!({
            "type": "trojan",
            "tag": "trojan-in",
            "listen": "0.0.0.0",
            "listen_port": 443,
            "users": [{ "name": "user1", "password": "secret" }],
            "tls": {
                "enabled": true,
                "certificate_path": "/cert.pem",
                "key_path": "/key.pem"
            }
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert!(matches!(ib, InboundConfig::Trojan(_)));
    }

    #[test]
    fn parse_shadowsocks_inbound() {
        let v = json!({
            "type": "shadowsocks",
            "tag": "ss-in",
            "listen": "0.0.0.0",
            "listen_port": 8388,
            "method": "2022-blake3-aes-256-gcm",
            "password": "base64password"
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert!(matches!(ib, InboundConfig::Shadowsocks(_)));
        if let InboundConfig::Shadowsocks(c) = &ib {
            assert_eq!(c.method, "2022-blake3-aes-256-gcm");
            assert_eq!(c.password.as_deref(), Some("base64password"));
        }
    }

    #[test]
    fn parse_hysteria2_inbound() {
        let v = json!({
            "type": "hysteria2",
            "tag": "hy2-in",
            "listen": "0.0.0.0",
            "listen_port": 443,
            "users": [{ "password": "mypassword" }],
            "tls": {
                "enabled": true,
                "certificate_path": "/cert.pem",
                "key_path": "/key.pem"
            }
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert!(matches!(ib, InboundConfig::Hysteria2(_)));
    }

    #[test]
    fn parse_tuic_inbound() {
        let v = json!({
            "type": "tuic",
            "tag": "tuic-in",
            "listen": "0.0.0.0",
            "listen_port": 443,
            "users": [
                { "name": "user1", "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "password": "pass" }
            ],
            "tls": {
                "enabled": true,
                "certificate_path": "/cert.pem",
                "key_path": "/key.pem"
            }
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert!(matches!(ib, InboundConfig::Tuic(_)));
    }

    #[test]
    fn parse_vless_reality_inbound() {
        let v = json!({
            "type": "vless",
            "tag": "vless-reality-in",
            "listen": "0.0.0.0",
            "listen_port": 443,
            "users": [
                { "name": "user1", "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "flow": "xtls-rprx-vision" }
            ],
            "tls": {
                "enabled": true,
                "reality": {
                    "enabled": true,
                    "private_key": "private_key_base64",
                    "public_key": "public_key_base64",
                    "short_ids": ["abc123"],
                    "dest": "example.com:443",
                    "server_name": "example.com"
                }
            }
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert!(matches!(ib, InboundConfig::Vless(_)));
        if let InboundConfig::Vless(c) = &ib {
            let tls = c.tls.as_ref().unwrap();
            assert!(tls.reality.is_some());
            let reality = tls.reality.as_ref().unwrap();
            assert_eq!(reality.dest, "example.com:443");
        }
    }
}
