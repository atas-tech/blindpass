// SPDX-License-Identifier: AGPL-3.0-only

//! Maintained TLS with bounded parallel handshakes. PEM buffers are private
//! SecretBytes; rustls retains server key state until its config is released.

use axum::serve::Listener;
use blindpass_core::deployment::read_private_file;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

const MAX_HANDSHAKES: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub fn load_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, &'static str> {
    let cert_pem = read_private_file(cert, 256 * 1024).map_err(|_| "BLINDPASS_TLS_CERT_FILE")?;
    let key_pem = read_private_file(key, 16 * 1024).map_err(|_| "BLINDPASS_TLS_KEY_FILE")?;
    let certificates = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "BLINDPASS_TLS_CERT_FILE")?;
    if certificates.is_empty() || certificates.len() > 16 {
        return Err("BLINDPASS_TLS_CERT_FILE");
    }
    let private_key =
        PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|_| "BLINDPASS_TLS_KEY_FILE")?;
    let provider = tokio_rustls::rustls::crypto::ring::default_provider();
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| "BLINDPASS_TLS_CERT_FILE")?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|_| "BLINDPASS_TLS_KEY_FILE")?;
    // Axum's current controller profile is HTTP/1.1 only.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    handshakes: JoinSet<Option<(TlsStream<TcpStream>, SocketAddr)>>,
}

impl TlsListener {
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>) -> Self {
        Self {
            listener,
            acceptor: TlsAcceptor::from(config),
            handshakes: JoinSet::new(),
        }
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            tokio::select! {
                completed = self.handshakes.join_next(), if !self.handshakes.is_empty() => {
                    if let Some(Ok(Some(connection))) = completed {
                        return connection;
                    }
                }
                incoming = self.listener.accept(), if self.handshakes.len() < MAX_HANDSHAKES => {
                    match incoming {
                        Ok((stream, peer)) => {
                            let acceptor = self.acceptor.clone();
                            self.handshakes.spawn(async move {
                                match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                                    Ok(Ok(stream)) => Some((stream, peer)),
                                    _ => None,
                                }
                            });
                        }
                        Err(_) => {
                            tracing::warn!(event = "listener_accept_failed");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}
