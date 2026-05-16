//! `dobby pair` — workstation pairs with a Keeper via mDNS (LAN) or an
//! explicit address (remote / hostile LAN). `--fingerprint` pins the
//! Keeper TLS certificate and aborts on mismatch. See issue #1
//! § Network discovery (mDNS) and Authentication.

// CLI commands write user-facing output to stdout. Workspace lints deny
// `print_stdout` to keep library code on tracing — this module is the
// designated print-out layer for `dobby pair`.
#![allow(clippy::print_stdout)]

use std::{
    env,
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{Context as _, bail};
use clap::Args;
use dobby_core::{auth, tls};
use dobby_proto::v1::{PairRequest, keeper_service_client::KeeperServiceClient};
use http::Uri;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{
        CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
        pki_types::{CertificateDer, ServerName, UnixTime},
    },
};
use tonic::transport::Endpoint;
use tower_service::Service;

#[derive(Debug, Args)]
pub struct PairArgs {
    /// Explicit Keeper address (`host:port`). Omit to auto-discover via mDNS.
    pub address: Option<String>,

    /// One-time bootstrap token from `dobby keeper init`.
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,

    /// Expected TLS cert SHA-256 fingerprint. Skips the TOFU prompt.
    #[arg(long, value_name = "SHA256")]
    pub fingerprint: Option<String>,
}

#[derive(Debug)]
struct KeeperEndpoint {
    address: String,
    host: String,
    port: u16,
}

#[derive(Debug, Clone)]
struct PinnedTlsConnector {
    host: String,
    port: u16,
    expected_fingerprint: [u8; 32],
    crypto_provider: Arc<CryptoProvider>,
}

#[derive(Debug)]
struct FingerprintVerifier {
    expected_fingerprint: [u8; 32],
    crypto_provider: Arc<CryptoProvider>,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub async fn run(args: PairArgs) -> anyhow::Result<()> {
    let endpoint = parse_endpoint(args.address.as_deref())?;
    let token = args
        .token
        .as_deref()
        .context("missing --token from `dobby keeper init`")?;
    let fingerprint_hex = args
        .fingerprint
        .as_deref()
        .context("missing --fingerprint from `dobby keeper show-fingerprint`")?;
    let expected_fingerprint = tls::parse_fingerprint_hex(fingerprint_hex)?;

    let config_dir = workstation_config_dir()?;
    let key_path = config_dir.join("key.ed25519");
    let pairing_path = config_dir.join("pairing.toml");
    let keypair = auth::load_or_create_workstation_keypair(&key_path)?;
    let public_key = keypair.public_key_bytes();
    let challenge = auth::pair_challenge(&expected_fingerprint, &public_key);
    let signature = keypair.sign(&challenge);

    let channel = pinned_channel(&endpoint, expected_fingerprint).await?;
    let mut client = KeeperServiceClient::new(channel);
    let response = client
        .pair(PairRequest {
            workstation_pubkey: public_key.to_vec(),
            bootstrap_token: token.to_owned(),
            tls_fingerprint_sha256: expected_fingerprint.to_vec(),
            workstation_signature: signature.to_vec(),
        })
        .await?
        .into_inner();

    if response.tls_fingerprint_sha256 != expected_fingerprint {
        bail!("Keeper Pair response returned a different TLS fingerprint");
    }

    auth::save_workstation_pairing(
        &pairing_path,
        &auth::WorkstationPairing {
            keeper_address: endpoint.address,
            tls_fingerprint_sha256: fingerprint_hex.to_owned(),
            workstation_pubkey: const_hex::encode(public_key),
        },
    )?;

    println!("✓ Paired workstation with Keeper");
    println!("✓ Workstation key        → {}", key_path.display());
    println!("✓ Pairing metadata       → {}", pairing_path.display());
    Ok(())
}

fn parse_endpoint(address: Option<&str>) -> anyhow::Result<KeeperEndpoint> {
    let Some(address) = address else {
        bail!("mDNS auto-discovery is not implemented yet; pass Keeper address as host:port");
    };
    let uri_text = if address.starts_with("http://") || address.starts_with("https://") {
        address.to_owned()
    } else {
        format!("https://{address}")
    };
    let uri: Uri = uri_text
        .parse()
        .context("Keeper address must be host:port")?;
    let host = uri
        .host()
        .context("Keeper address must include a host")?
        .to_owned();
    let port = uri
        .port_u16()
        .context("Keeper address must include an explicit port")?;
    let address = uri
        .authority()
        .context("Keeper address must include host:port authority")?
        .as_str()
        .to_owned();
    Ok(KeeperEndpoint {
        address,
        host,
        port,
    })
}

fn workstation_config_dir() -> anyhow::Result<PathBuf> {
    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("dobby"));
    }
    let home = env::var_os("HOME").context("HOME is not set; cannot resolve ~/.config/dobby")?;
    Ok(PathBuf::from(home).join(".config/dobby"))
}

async fn pinned_channel(
    endpoint: &KeeperEndpoint,
    expected_fingerprint: [u8; 32],
) -> anyhow::Result<tonic::transport::Channel> {
    let uri = format!("http://{}", endpoint.address);
    let connector =
        PinnedTlsConnector::new(endpoint.host.clone(), endpoint.port, expected_fingerprint);
    Endpoint::from_shared(uri)?
        .connect_with_connector(connector)
        .await
        .map_err(Into::into)
}

impl PinnedTlsConnector {
    fn new(host: String, port: u16, expected_fingerprint: [u8; 32]) -> Self {
        Self {
            host,
            port,
            expected_fingerprint,
            crypto_provider: default_crypto_provider(),
        }
    }
}

impl Service<Uri> for PinnedTlsConnector {
    type Response = TokioIo<TlsStream<TcpStream>>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Uri) -> Self::Future {
        let host = self.host.clone();
        let port = self.port;
        let expected_fingerprint = self.expected_fingerprint;
        let crypto_provider = self.crypto_provider.clone();

        Box::pin(async move {
            let tcp = TcpStream::connect((host.as_str(), port)).await?;
            let mut tls_config = ClientConfig::builder_with_provider(crypto_provider.clone())
                .with_safe_default_protocol_versions()?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(FingerprintVerifier {
                    expected_fingerprint,
                    crypto_provider,
                }))
                .with_no_client_auth();
            tls_config.alpn_protocols.push(b"h2".to_vec());

            let server_name = ServerName::try_from(host)?;
            let stream = TlsConnector::from(Arc::new(tls_config))
                .connect(server_name, tcp)
                .await?;
            Ok(TokioIo::new(stream))
        })
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual = tls::fingerprint_sha256_bytes_from_der(end_entity.as_ref());
        if actual == self.expected_fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn default_crypto_provider() -> Arc<CryptoProvider> {
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
        path::Path,
        time::Duration,
    };

    use dobby_core::keeper_init;
    use tokio::sync::oneshot;

    use super::*;

    fn pick_port() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);
        addr
    }

    fn keeper_init_request(dir: &Path, keeper_ip: IpAddr) -> keeper_init::Request {
        keeper_init::Request {
            dir: dir.to_path_buf(),
            keeper_ip,
            gateway: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dns_upstream: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            subnet: "10.0.0.0/24".into(),
            static_range: "10.0.0.200-10.0.0.250".into(),
            bridge: "vmbr0".into(),
            force: false,
        }
    }

    #[tokio::test]
    async fn pinned_tls_channel_pairs_against_keeper() {
        let tmp = tempfile::tempdir().unwrap();
        let bind_addr = pick_port();
        let init = keeper_init::init(&keeper_init_request(tmp.path(), bind_addr.ip())).unwrap();
        let tls_config = dobby_keeper::test_support::load_server_tls(tmp.path()).unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let server_handle = tokio::spawn({
            let tmp_path = tmp.path().to_path_buf();
            async move {
                dobby_keeper::test_support::serve(bind_addr, tls_config, tmp_path, async {
                    let _ = shutdown_rx.await;
                })
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let endpoint = KeeperEndpoint {
            address: bind_addr.to_string(),
            host: bind_addr.ip().to_string(),
            port: bind_addr.port(),
        };
        let fingerprint = tls::parse_fingerprint_hex(&init.tls_fingerprint_sha256).unwrap();
        let channel = pinned_channel(&endpoint, fingerprint).await.unwrap();
        let mut client = KeeperServiceClient::new(channel);
        let keypair = auth::WorkstationKeypair::generate().unwrap();
        let public_key = keypair.public_key_bytes();
        let challenge = auth::pair_challenge(&fingerprint, &public_key);
        let signature = keypair.sign(&challenge);

        let response = client
            .pair(PairRequest {
                workstation_pubkey: public_key.to_vec(),
                bootstrap_token: init.bootstrap_token.to_string(),
                tls_fingerprint_sha256: fingerprint.to_vec(),
                workstation_signature: signature.to_vec(),
            })
            .await
            .expect("pair over pinned TLS")
            .into_inner();
        assert_eq!(response.tls_fingerprint_sha256, fingerprint);

        let _ = shutdown_tx.send(());
        server_handle.await.expect("join").expect("serve");
    }
}
