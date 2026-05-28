//! VMess 服务端入站
//!
//! 支持 VMess AEAD 协议（移除对 alterId > 0 的 MD5 老协议支持）。
//!
//! 协议参考：https://xtls.github.io/development/protocols/vmess.html
//!
//! VMess TCP 请求头：
//! [Auth ID 16B (AES-128-GCM enc timestamp)] [Header Length 2B + tag] [Header ...]
//! Header: [Ver 1B][IV 16B][Key 16B][RespV 1B][Opt 1B][Padding+Sec 1B][Reserved 1B][Cmd 1B][Port 2B][Atyp 1B][Addr ...][RandLen]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tracing::{debug, error, info};

use crate::{
    config::inbound::VmessInboundConfig,
    inbound::{InboundTcpStream, SniffedStream, Target},
};

pub struct VmessInbound {
    config: VmessInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
}

impl VmessInbound {
    pub fn new(config: VmessInboundConfig, tcp_tx: mpsc::Sender<InboundTcpStream>) -> Self {
        Self { config, tcp_tx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr =
            format!("{}:{}", self.config.listen, self.config.listen_port).parse()?;
        let tag = Arc::new(self.config.tag.clone());

        // 解析所有用户 UUID（16 字节）
        let users: Arc<Vec<[u8; 16]>> = Arc::new(
            self.config
                .users
                .iter()
                .map(|u| parse_uuid(&u.uuid))
                .collect::<anyhow::Result<Vec<_>>>()
                .map_err(|e| anyhow::anyhow!("vmess inbound: invalid user UUID: {e}"))?,
        );

        // 构建 TLS acceptor
        #[cfg(feature = "outbound-net")]
        let tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>> = build_tls_acceptor(&self.config)?;
        #[cfg(not(feature = "outbound-net"))]
        if self.config.tls.as_ref().is_some_and(|t| t.enabled) {
            warn!(tag = %tag, "vmess inbound: TLS requested but feature outbound-net is not enabled");
        }

        info!(tag = %tag, addr = %bind, "vmess inbound starting");
        let listener = TcpListener::bind(bind).await?;

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!(err = %e, "vmess inbound accept error");
                    continue;
                }
            };

            let tcp_tx = self.tcp_tx.clone();
            let tag = tag.clone();
            let users = users.clone();

            #[cfg(feature = "outbound-net")]
            let acceptor = tls_acceptor.clone();

            tokio::spawn(async move {
                #[cfg(feature = "outbound-net")]
                let res = handle_conn_tls(stream, peer, users, acceptor, tcp_tx, &tag).await;
                #[cfg(not(feature = "outbound-net"))]
                let res = handle_conn_plain(stream, peer, users, tcp_tx, &tag).await;
                if let Err(e) = res {
                    debug!(peer = %peer, err = %e, "vmess inbound conn error");
                }
            });
        }
    }
}

#[cfg(feature = "outbound-net")]
fn build_tls_acceptor(cfg: &VmessInboundConfig) -> anyhow::Result<Option<Arc<tokio_rustls::TlsAcceptor>>> {
    match &cfg.tls {
        Some(tls) if tls.enabled => {
            let a = crate::inbound::server_tls::build_acceptor(tls)?;
            Ok(Some(Arc::new(a)))
        }
        _ => Ok(None),
    }
}

#[cfg(feature = "outbound-net")]
async fn handle_conn_tls(
    stream: TcpStream,
    peer: SocketAddr,
    users: Arc<Vec<[u8; 16]>>,
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: &str,
) -> anyhow::Result<()> {
    if let Some(acceptor) = tls_acceptor {
        let tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|e| anyhow::anyhow!("vmess TLS handshake: {e}"))?;
        process_vmess_and_relay(tls_stream, peer, &users, tcp_tx, tag).await
    } else {
        handle_conn_plain(stream, peer, users, tcp_tx, tag).await
    }
}

/// 无 TLS：解析 VMess 头并送入 dispatcher
async fn handle_conn_plain(
    mut stream: TcpStream,
    peer: SocketAddr,
    users: Arc<Vec<[u8; 16]>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: &str,
) -> anyhow::Result<()> {
    let (target, resp_key, resp_iv, resp_v) =
        decode_vmess_header(&mut stream, &users).await?;

    // 发送 VMess 响应头（加密）
    send_vmess_response(&mut stream, &resp_key, &resp_iv, resp_v).await?;

    debug!(peer = %peer, target = %target, "vmess inbound: accepted (plain)");

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

/// TLS 模式：解析 VMess 头后直接 relay
async fn process_vmess_and_relay<S>(
    mut stream: S,
    peer: SocketAddr,
    users: &[[u8; 16]],
    _tcp_tx: mpsc::Sender<InboundTcpStream>,
    _tag: &str,
        decode_vmess_header(&mut stream, users).await?;
    send_vmess_response(&mut stream, &resp_key, &resp_iv, resp_v).await?;

    debug!(peer = %peer, target = %target, "vmess inbound: accepted (TLS), direct relay");

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

    info!(peer = %peer, target = %target, "vmess inbound: relaying");

    let (mut r1, mut w1) = tokio::io::split(stream);
    let (mut r2, mut w2) = outbound.into_split();
    let up = tokio::io::copy(&mut r1, &mut w2);
    let dn = tokio::io::copy(&mut r2, &mut w1);
    tokio::try_join!(up, dn).ok();

    Ok(())
}

// ── VMess AEAD 协议解析 ───────────────────────────────────────────────────────
// 返回: (Target, response_key[16], response_iv[16], response_v)

async fn decode_vmess_header<S: tokio::io::AsyncReadExt + Unpin>(
    stream: &mut S,
    users: &[[u8; 16]],
) -> anyhow::Result<(Target, [u8; 16], [u8; 16], u8)> {
    use aes_gcm::{aead::{AeadInPlace, KeyInit}, Aes128Gcm};

    // ── 读取 Auth ID (16B)，并匹配用户 ───────────────────────────────────────
    let mut auth_id = [0u8; 16];
    stream.read_exact(&mut auth_id).await?;

    // 暴力尝试每个用户的 cmd_key 解密 Auth ID
    let mut matched_cmd_key: Option<[u8; 16]> = None;
    for &uuid in users {
        let cmd_key = vmess_cmd_key(&uuid);
        // Auth ID = AES-128(key=kdf16(cmdKey, "AES Auth ID Encryption"), timestamp BE 8B + rand 4B + crc 4B)
        if verify_auth_id(&auth_id, &cmd_key) {
            matched_cmd_key = Some(cmd_key);
            break;
        }
    }
    let cmd_key = matched_cmd_key
        .ok_or_else(|| anyhow::anyhow!("vmess: no matching user for auth ID"))?;

    // ── 读取加密 Header Length (2B + 4B tag under GCM) ───────────────────────
    let mut enc_len_buf = [0u8; 2 + 4]; // 2B length + 4B AESGCM-4 tag
    stream.read_exact(&mut enc_len_buf).await?;

    // key = kdf16(cmdKey, "AEAD Header Length Key", auth_id, connectionNonce)
    // nonce = kdf12(cmdKey, "AEAD Header Length IV", auth_id, connectionNonce)
    // connectionNonce = enc_len_buf[:8] after reading the header nonce
    // Simplified: read connection nonce from stream first
    let mut conn_nonce = [0u8; 8];
    stream.read_exact(&mut conn_nonce).await?;

    let hlen_key = kdf16(&cmd_key, &["AEAD Header Length Key", &hex_bytes(&auth_id), &hex_bytes(&conn_nonce)]);
    let hlen_nonce = kdf12(&cmd_key, &["AEAD Header Length IV", &hex_bytes(&auth_id), &hex_bytes(&conn_nonce)]);

    let cipher = Aes128Gcm::new_from_slice(&hlen_key)
        .map_err(|_| anyhow::anyhow!("vmess: AES key error"))?;
    let nonce_val = aes_gcm::Nonce::from_slice(&hlen_nonce);
    let mut len_data = enc_len_buf.to_vec();
    cipher
        .decrypt_in_place(nonce_val, &auth_id, &mut len_data)
        .map_err(|_| anyhow::anyhow!("vmess: header length decryption failed"))?;

    let header_len = u16::from_be_bytes([len_data[0], len_data[1]]) as usize;
    anyhow::ensure!(header_len > 0 && header_len < 65536, "vmess: invalid header length: {header_len}");

    // ── 读取并解密 Header ─────────────────────────────────────────────────────
    let header_key = kdf16(&cmd_key, &["AEAD Header Key", &hex_bytes(&auth_id), &hex_bytes(&conn_nonce)]);
    let header_nonce = kdf12(&cmd_key, &["AEAD Header IV", &hex_bytes(&auth_id), &hex_bytes(&conn_nonce)]);

    let mut enc_header = vec![0u8; header_len + 16]; // header + GCM tag
    stream.read_exact(&mut enc_header).await?;

    let header_cipher = Aes128Gcm::new_from_slice(&header_key)
        .map_err(|_| anyhow::anyhow!("vmess: AES header key error"))?;
    let header_nonce_val = aes_gcm::Nonce::from_slice(&header_nonce);
    header_cipher
        .decrypt_in_place(header_nonce_val, &auth_id, &mut enc_header)
        .map_err(|_| anyhow::anyhow!("vmess: header decryption failed"))?;
    enc_header.truncate(header_len);

    // ── 解析 Header 字段 ──────────────────────────────────────────────────────
    // [Ver 1B][IV 16B][Key 16B][RespV 1B][Opt 1B][Padding+Sec 1B][Reserved 1B][Cmd 1B][Port 2B][Atyp 1B][Addr...][PaddingLen ...][Checksum 4B]
    let h = &enc_header;
    let mut pos = 0;

    let ver = h[pos]; pos += 1;
    anyhow::ensure!(ver == 1, "vmess: unsupported version: {ver}");

    let _data_iv = &h[pos..pos+16]; pos += 16;
    let _data_key = &h[pos..pos+16]; pos += 16;
    let resp_v = h[pos]; pos += 1;
    let _opt = h[pos]; pos += 1;

    let padding_sec = h[pos]; pos += 1;
    let padding_len = (padding_sec >> 4) as usize;
    let _security = padding_sec & 0x0f;
    pos += 1; // reserved

    let cmd = h[pos]; pos += 1;
    anyhow::ensure!(cmd == 0x01, "vmess: only TCP (cmd=1) supported");

    let port = u16::from_be_bytes([h[pos], h[pos+1]]); pos += 2;
    let atyp = h[pos]; pos += 1;

    let target = match atyp {
        0x01 => {
            let ip = Ipv4Addr::new(h[pos], h[pos+1], h[pos+2], h[pos+3]); pos += 4; let _ = pos;
            Target::Socket(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            let dlen = h[pos] as usize; pos += 1;
            let domain = String::from_utf8(h[pos..pos+dlen].to_vec())?; pos += dlen; let _ = pos;
            Target::Domain(domain, port)
        }
        0x03 => {
            let ip_bytes: [u8; 16] = h[pos..pos+16].try_into()?; pos += 16; let _ = pos;
            Target::Socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port))
        }
        other => anyhow::bail!("vmess: unknown atyp 0x{other:02x}"),
    };

    let _ = pos + padding_len; // skip padding
    // last 4 bytes = FNV checksum (skip validation for now)

    // 计算响应密钥和 IV：response_key = MD5(data_key), response_iv = MD5(data_iv)
    let resp_key = {
        let data_key = &enc_header[1+16..1+16+16]; // 修正偏移
        md5_hash(data_key)
    };
    let resp_iv = {
        let data_iv = &enc_header[1..1+16];
        md5_hash(data_iv)
    };

    Ok((target, resp_key, resp_iv, resp_v))
}

async fn send_vmess_response<S: tokio::io::AsyncWriteExt + Unpin>(
    stream: &mut S,
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    resp_v: u8,
) -> anyhow::Result<()> {
    use aes_gcm::{aead::{AeadInPlace, KeyInit}, Aes128Gcm};

    // 响应头：[RespV 1B][Opt 1B][Cmd 1B][CmdLen 1B]
    let header = [resp_v, 0x00, 0x00, 0x00];

    let nonce = &resp_iv[..12];
    let cipher = Aes128Gcm::new_from_slice(resp_key)
        .map_err(|_| anyhow::anyhow!("vmess: resp key error"))?;
    let nonce_val = aes_gcm::Nonce::from_slice(nonce);
    let mut enc = header.to_vec();
    cipher
        .encrypt_in_place(nonce_val, b"", &mut enc)
        .map_err(|_| anyhow::anyhow!("vmess: resp encrypt failed"))?;

    stream.write_all(&enc).await?;
    Ok(())
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

fn vmess_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    use md5::{Digest as _, Md5};
    // cmd_key = MD5(uuid_bytes + "c48619fe-8f02-49e0-b9e9-edf763e17e21")
    let salt = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
    let mut h = Md5::new();
    h.update(uuid);
    h.update(salt);
    h.finalize().into()
}

fn verify_auth_id(auth_id: &[u8; 16], cmd_key: &[u8; 16]) -> bool {
    use aes::Aes128;
    use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};

    let aead_key = kdf16(cmd_key, &["AES Auth ID Encryption"]);
    let cipher = Aes128::new_from_slice(&aead_key).unwrap();
    let mut block = *GenericArray::from_slice(auth_id);
    cipher.decrypt_block(&mut block);

    // Decrypted: [timestamp 8B][rand 4B][crc 4B]
    let ts_bytes: [u8; 8] = block[..8].try_into().unwrap();
    let ts = i64::from_be_bytes(ts_bytes);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let diff = (ts - now).abs();
    if diff > 120 {
        return false; // 时间误差超过 2 分钟
    }

    // 验证 CRC（block[12..16] = CRC32 of block[0..12]）
    let expected_crc = crc32fast::hash(&block[..12]);
    let actual_crc = u32::from_be_bytes(block[12..16].try_into().unwrap());
    expected_crc == actual_crc
}

fn kdf16(key: &[u8], paths: &[&str]) -> [u8; 16] {
    let hash = kdf_sha256(key, paths);
    hash[..16].try_into().unwrap()
}

fn kdf12(key: &[u8], paths: &[&str]) -> [u8; 12] {
    let hash = kdf_sha256(key, paths);
    hash[..12].try_into().unwrap()
}

fn kdf_sha256(key: &[u8], paths: &[&str]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut current = key.to_vec();
    for path in paths {
        let mut mac = HmacSha256::new_from_slice(&current).unwrap();
        mac.update(path.as_bytes());
        current = mac.finalize().into_bytes().to_vec();
    }
    current[..32].try_into().unwrap()
}

fn md5_hash(data: &[u8]) -> [u8; 16] {
    use md5::{Digest as _, Md5};
    Md5::digest(data).into()
}

fn hex_bytes(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
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
