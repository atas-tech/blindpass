// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded local readiness probe. It reads no controller key/store configuration.
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use tokio_rustls::rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

struct Transport {
    stream: TcpStream,
    expires: Instant,
}
impl Transport {
    fn remaining(&self) -> io::Result<Duration> {
        self.expires
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    }
}
impl Read for Transport {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}
impl Write for Transport {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

pub fn run() -> Result<(), String> {
    probe().map_err(|_| "readiness probe failed".to_owned())
}

fn probe() -> Result<(), ()> {
    let expires = Instant::now() + Duration::from_secs(2);
    let mut address: SocketAddr = std::env::var("BLINDPASS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:3200".into())
        .parse()
        .map_err(|_| ())?;
    // A config value cannot make the probe contact arbitrary remote hosts.
    address.set_ip(match address.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    });
    let stream =
        TcpStream::connect_timeout(&address, Duration::from_millis(750)).map_err(|_| ())?;
    let mut transport = Transport { stream, expires };
    if std::env::var_os("BLINDPASS_TLS_CERT_FILE").is_some() {
        let name =
            ServerName::try_from(std::env::var("BLINDPASS_HEALTH_TLS_NAME").map_err(|_| ())?)
                .map_err(|_| ())?;
        let ca = std::env::var_os("BLINDPASS_HEALTH_CA_FILE")
            .unwrap_or_else(|| "/etc/ssl/certs/ca-certificates.crt".into());
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(0x20000 | 0x800)
            .open(ca)
            .map_err(|_| ())?;
        let metadata = file.metadata().map_err(|_| ())?;
        if !metadata.is_file() || metadata.len() > 1024 * 1024 {
            return Err(());
        }
        let mut pem = Vec::new();
        file.take(1024 * 1024 + 1)
            .read_to_end(&mut pem)
            .map_err(|_| ())?;
        if pem.len() > 1024 * 1024 {
            return Err(());
        }
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&pem) {
            roots.add(cert.map_err(|_| ())?).map_err(|_| ())?;
        }
        if roots.is_empty() {
            return Err(());
        }
        let provider = tokio_rustls::rustls::crypto::ring::default_provider();
        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|_| ())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connection = ClientConnection::new(Arc::new(config), name).map_err(|_| ())?;
        request(&mut StreamOwned::new(connection, transport))
    } else {
        request(&mut transport)
    }
}

fn request(stream: &mut (impl Read + Write)) -> Result<(), ()> {
    stream
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|_| ())?;
    let mut bytes = Vec::new();
    // TLS may close without close_notify after a complete HTTP response.
    // Accept only a complete, length-bound body; incomplete responses fail.
    let result = stream.take(8193).read_to_end(&mut bytes);
    if result.is_err()
        && !matches!(
            result.as_ref().err().map(io::Error::kind),
            Some(io::ErrorKind::UnexpectedEof)
        )
    {
        return Err(());
    }
    if bytes.len() > 8192 {
        return Err(());
    }
    let boundary = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(())?;
    let header = std::str::from_utf8(&bytes[..boundary]).map_err(|_| ())?;
    let mut lines = header.split("\r\n");
    let status = lines.next().ok_or(())?;
    if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.0 200 ") {
        return Err(());
    }
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(())?;
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(());
            }
            length = Some(value.trim().parse::<usize>().map_err(|_| ())?);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(());
        }
    }
    let body = &bytes[boundary + 4..];
    if length != Some(body.len()) {
        return Err(());
    }
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| ())?;
    if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true)
        || value
            .pointer("/checks/database")
            .and_then(serde_json::Value::as_str)
            != Some("up")
    {
        return Err(());
    }
    Ok(())
}
