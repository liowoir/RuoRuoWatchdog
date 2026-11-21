//! 讀遠端 HTTPS 伺服器憑證上的網域名稱（SAN / CN）。
//! 只做 TLS 握手、不送任何 HTTP 資料；不驗證憑證（目的只是讀名稱，不是建立可信連線）。

use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

#[derive(Debug)]
struct AcceptAny(Vec<SignatureScheme>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.clone()
    }
}

fn config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let schemes = provider.signature_verification_algorithms.supported_schemes();
        let cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(schemes)))
            .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

pub fn cert_names(ip: IpAddr, port: u16) -> Option<Vec<String>> {
    let addr = SocketAddr::new(ip, port);
    let mut sock = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    sock.set_write_timeout(Some(Duration::from_secs(3))).ok()?;
    let mut conn = ClientConnection::new(config(), ServerName::IpAddress(ip.into())).ok()?;
    let mut rounds = 0;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).ok()?;
        rounds += 1;
        if rounds > 20 {
            return None;
        }
    }
    let der = conn.peer_certificates()?.first()?.clone();
    conn.send_close_notify();
    let _ = conn.write_tls(&mut sock);
    let _ = sock.flush();

    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
    let mut names: Vec<String> = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for g in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(n) = g {
                let n = n.to_lowercase();
                if !names.contains(&n) {
                    names.push(n);
                }
            }
        }
    }
    if names.is_empty() {
        if let Some(cn) = cert.subject().iter_common_name().next().and_then(|c| c.as_str().ok()) {
            names.push(cn.to_lowercase());
        }
    }
    // 沒帶 SNI 時有些伺服器會回預設的假憑證（例如 invalid2.invalid），這些名稱沒有意義
    names.retain(|n| n.contains('.') && !n.ends_with(".invalid") && !n.ends_with(".local") && n != "localhost");
    names.truncate(5);
    Some(names)
}
