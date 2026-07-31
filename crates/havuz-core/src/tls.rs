//! TLS for backend connections.
//!
//! libpq's `sslmode` does not map onto rustls defaults. rustls only offers
//! "verify everything" out of the box, while `sslmode` has two intermediate
//! levels that real deployments depend on:
//!
//! | sslmode       | encrypt | verify chain | verify hostname |
//! |---------------|---------|--------------|-----------------|
//! | `disable`     | no      | -            | -               |
//! | `prefer`      | if offered | no        | no              |
//! | `require`     | yes     | no           | no              |
//! | `verify-ca`   | yes     | yes          | **no**          |
//! | `verify-full` | yes     | yes          | yes             |
//!
//! `verify-ca` is the awkward one and needs a custom verifier. It exists
//! because managed databases hand out certificates whose CN does not match the
//! address clients dial.

use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("unknown sslmode '{0}'")]
    UnknownMode(String),
    #[error("cannot read CA bundle {path}: {source}")]
    ReadCa {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("CA bundle {0} contains no certificates")]
    EmptyCa(String),
    #[error("CA bundle {path} is malformed: {source}")]
    BadCa {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("tls configuration rejected: {0}")]
    Rustls(#[from] RustlsError),
    #[error("no rustls crypto provider is installed")]
    NoProvider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SslMode {
    Disable,
    #[default]
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl SslMode {
    pub fn parse(value: &str) -> Result<Self, TlsError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "disable" | "off" => Ok(SslMode::Disable),
            // libpq's `allow` prefers plaintext and only upgrades on refusal.
            // havuz treats it as `prefer`, which is strictly safer.
            "allow" | "prefer" => Ok(SslMode::Prefer),
            "require" | "on" => Ok(SslMode::Require),
            "verify-ca" => Ok(SslMode::VerifyCa),
            "verify-full" => Ok(SslMode::VerifyFull),
            other => Err(TlsError::UnknownMode(other.to_string())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SslMode::Disable => "disable",
            SslMode::Prefer => "prefer",
            SslMode::Require => "require",
            SslMode::VerifyCa => "verify-ca",
            SslMode::VerifyFull => "verify-full",
        }
    }

    /// Whether havuz attempts a TLS upgrade at all.
    pub fn wants_tls(self) -> bool {
        !matches!(self, SslMode::Disable)
    }

    /// Whether a refused upgrade is fatal. `prefer` falls back to plaintext.
    pub fn requires_tls(self) -> bool {
        matches!(self, SslMode::Require | SslMode::VerifyCa | SslMode::VerifyFull)
    }

    pub fn verifies_chain(self) -> bool {
        matches!(self, SslMode::VerifyCa | SslMode::VerifyFull)
    }

    pub fn verifies_hostname(self) -> bool {
        matches!(self, SslMode::VerifyFull)
    }
}

/// Build a rustls client configuration matching `mode`.
///
/// `ca_path` overrides the system trust store and is required in practice for
/// managed databases that use a private CA.
pub fn client_config(mode: SslMode, ca_path: Option<&Path>) -> Result<Option<Arc<ClientConfig>>, TlsError> {
    if !mode.wants_tls() {
        return Ok(None);
    }

    let provider =
        CryptoProvider::get_default().cloned().unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

    let config = if mode.verifies_chain() {
        let roots = load_roots(ca_path)?;
        let builder = ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()?;
        if mode.verifies_hostname() {
            builder.with_root_certificates(roots).with_no_client_auth()
        } else {
            // verify-ca: chain is checked, hostname is not.
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ChainOnlyVerifier::new(roots, provider)))
                .with_no_client_auth()
        }
    } else {
        // require / prefer: encryption without authentication. This is what
        // libpq does, and it is vulnerable to an active MITM. We keep it
        // because refusing it would make havuz unusable against the many
        // databases that ship self-signed certificates, but it is never the
        // default in the UI.
        ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerification::new(provider)))
            .with_no_client_auth()
    };

    Ok(Some(Arc::new(config)))
}

/// Install the process-wide crypto provider. Idempotent.
pub fn install_default_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn load_roots(ca_path: Option<&Path>) -> Result<RootCertStore, TlsError> {
    let mut roots = RootCertStore::empty();

    match ca_path {
        Some(path) => {
            let display = path.display().to_string();
            let bytes = std::fs::read(path).map_err(|source| TlsError::ReadCa { path: display.clone(), source })?;
            let mut reader = std::io::BufReader::new(bytes.as_slice());
            let certs = rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| TlsError::BadCa { path: display.clone(), source })?;
            if certs.is_empty() {
                return Err(TlsError::EmptyCa(display));
            }
            for cert in certs {
                roots.add(cert)?;
            }
        }
        None => {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
    }

    Ok(roots)
}

/// `verify-ca`: validate the certificate chain against the trust store, but
/// accept any subject name.
#[derive(Debug)]
struct ChainOnlyVerifier {
    roots: RootCertStore,
    provider: Arc<CryptoProvider>,
}

impl ChainOnlyVerifier {
    fn new(roots: RootCertStore, provider: Arc<CryptoProvider>) -> Self {
        Self { roots, provider }
    }
}

impl ServerCertVerifier for ChainOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        // Deliberately skipping the subject-name check; that is the entire
        // difference between verify-ca and verify-full.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// `require` / `prefer`: encrypt, authenticate nothing.
#[derive(Debug)]
struct NoVerification {
    provider: Arc<CryptoProvider>,
}

impl NoVerification {
    fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sslmode_parsing_matches_libpq_names() {
        assert_eq!(SslMode::parse("disable").unwrap(), SslMode::Disable);
        assert_eq!(SslMode::parse("prefer").unwrap(), SslMode::Prefer);
        assert_eq!(SslMode::parse("require").unwrap(), SslMode::Require);
        assert_eq!(SslMode::parse("verify-ca").unwrap(), SslMode::VerifyCa);
        assert_eq!(SslMode::parse("VERIFY-FULL").unwrap(), SslMode::VerifyFull);
        // `allow` is folded into `prefer`: strictly safer, same observable
        // behaviour against every server that offers TLS.
        assert_eq!(SslMode::parse("allow").unwrap(), SslMode::Prefer);
        assert!(SslMode::parse("verify_full").is_err(), "underscore spelling is not libpq");
    }

    #[test]
    fn mode_predicates_form_the_expected_ladder() {
        let cases = [
            (SslMode::Disable, false, false, false, false),
            (SslMode::Prefer, true, false, false, false),
            (SslMode::Require, true, true, false, false),
            (SslMode::VerifyCa, true, true, true, false),
            (SslMode::VerifyFull, true, true, true, true),
        ];
        for (mode, wants, requires, chain, hostname) in cases {
            assert_eq!(mode.wants_tls(), wants, "{mode:?} wants_tls");
            assert_eq!(mode.requires_tls(), requires, "{mode:?} requires_tls");
            assert_eq!(mode.verifies_chain(), chain, "{mode:?} verifies_chain");
            assert_eq!(mode.verifies_hostname(), hostname, "{mode:?} verifies_hostname");
        }
    }

    #[test]
    fn disable_produces_no_tls_config() {
        install_default_provider();
        assert!(client_config(SslMode::Disable, None).unwrap().is_none());
    }

    #[test]
    fn every_tls_mode_builds_a_config() {
        install_default_provider();
        for mode in [SslMode::Prefer, SslMode::Require, SslMode::VerifyCa, SslMode::VerifyFull] {
            let config = client_config(mode, None).unwrap();
            assert!(config.is_some(), "{mode:?} must produce a client config");
        }
    }

    #[test]
    fn missing_ca_bundle_is_reported_clearly() {
        install_default_provider();
        let err = client_config(SslMode::VerifyFull, Some(Path::new("/nonexistent/ca.pem"))).unwrap_err();
        assert!(matches!(err, TlsError::ReadCa { .. }), "got {err:?}");
    }

    #[test]
    fn empty_ca_bundle_is_rejected_rather_than_silently_trusting_nothing() {
        install_default_provider();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, b"# no certificates here\n").unwrap();

        let err = client_config(SslMode::VerifyCa, Some(&path)).unwrap_err();
        assert!(matches!(err, TlsError::EmptyCa(_)), "got {err:?}");
    }

    #[test]
    fn serde_uses_libpq_spelling() {
        assert_eq!(serde_json::to_string(&SslMode::VerifyFull).unwrap(), "\"verify-full\"");
        let parsed: SslMode = serde_json::from_str("\"verify-ca\"").unwrap();
        assert_eq!(parsed, SslMode::VerifyCa);
    }
}
