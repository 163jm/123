//! 服务端 TLS/Reality 配置构建工具
//!
//! 供 VLESS/VMess/Trojan/SS 等入站复用，统一处理证书加载。

use std::{io::BufReader, sync::Arc};

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use tokio_rustls::TlsAcceptor;

use crate::config::inbound::ServerTlsConfig;

/// 从 ServerTlsConfig 构建 rustls ServerConfig
pub fn build_server_config(tls: &ServerTlsConfig) -> anyhow::Result<Arc<ServerConfig>> {
    // 加载证书链
    let certs = load_certs(tls)?;
    // 加载私钥
    let key = load_key(tls)?;

    let mut alpn = tls.alpn.clone();
    if alpn.is_empty() {
        // 默认 ALPN
        alpn = vec!["h2".to_string(), "http/1.1".to_string()];
    }

    let alpn_bytes: Vec<Vec<u8>> = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("TLS server config error: {e}"))?;

    let mut config = config;
    config.alpn_protocols = alpn_bytes;

    Ok(Arc::new(config))
}

/// 构建 TlsAcceptor
pub fn build_acceptor(tls: &ServerTlsConfig) -> anyhow::Result<TlsAcceptor> {
    let config = build_server_config(tls)?;
    Ok(TlsAcceptor::from(config))
}

fn load_certs(tls: &ServerTlsConfig) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    // 优先使用 certificate_path
    if let Some(path) = &tls.certificate_path {
        let data = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("failed to read certificate from {path}: {e}"))?;
        let mut reader = BufReader::new(data.as_slice());
        let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
        return certs.map_err(|e| anyhow::anyhow!("failed to parse certificate: {e}"));
    }
    // 使用内嵌 PEM 字符串
    if !tls.certificate.is_empty() {
        let pem = tls.certificate.join("\n");
        let mut reader = BufReader::new(pem.as_bytes());
        let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
        return certs.map_err(|e| anyhow::anyhow!("failed to parse inline certificate: {e}"));
    }
    anyhow::bail!("TLS configuration missing certificate (set certificate_path or certificate)")
}

fn load_key(tls: &ServerTlsConfig) -> anyhow::Result<PrivateKeyDer<'static>> {
    // 优先使用 key_path
    if let Some(path) = &tls.key_path {
        let data = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("failed to read private key from {path}: {e}"))?;
        let mut reader = BufReader::new(data.as_slice());
        return read_private_key(&mut reader)
            .map_err(|e| anyhow::anyhow!("failed to parse private key from {path}: {e}"));
    }
    // 使用内嵌 PEM 字符串
    if !tls.key.is_empty() {
        let pem = tls.key.join("\n");
        let mut reader = BufReader::new(pem.as_bytes());
        return read_private_key(&mut reader)
            .map_err(|e| anyhow::anyhow!("failed to parse inline private key: {e}"));
    }
    anyhow::bail!("TLS configuration missing private key (set key_path or key)")
}

fn read_private_key(
    reader: &mut BufReader<&[u8]>,
) -> anyhow::Result<PrivateKeyDer<'static>> {
    // 尝试 PKCS8，再尝试 RSA
    let items: Vec<_> = rustls_pemfile::read_all(reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("PEM read error: {e}"))?;

    for item in items {
        match item {
            rustls_pemfile::Item::Pkcs8Key(key) => return Ok(PrivateKeyDer::Pkcs8(key)),
            rustls_pemfile::Item::Sec1Key(key) => return Ok(PrivateKeyDer::Sec1(key)),
            rustls_pemfile::Item::Pkcs1Key(key) => return Ok(PrivateKeyDer::Pkcs1(key)),
            _ => {}
        }
    }
    anyhow::bail!("no private key found in PEM data")
}
