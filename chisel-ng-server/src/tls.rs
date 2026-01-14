//! TLS configuration for the server

use anyhow::{Context, Result};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fs;
use std::io::BufReader;
use std::path::Path;
use tracing::{debug, trace};

/// Load TLS configuration from certificate and key files
pub async fn load_tls_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig> {
    trace!("Loading certificate from {:?}", cert_path);
    trace!("Loading private key from {:?}", key_path);

    // Read certificate chain
    let cert_file = fs::File::open(cert_path).context("Failed to open certificate file")?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate")?;

    if certs.is_empty() {
        anyhow::bail!("No certificates found in certificate file");
    }

    debug!("Loaded {} certificate(s)", certs.len());

    // Read private key
    let key_file = fs::File::open(key_path).context("Failed to open key file")?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("Failed to read private key")?
        .context("No private key found in key file")?;

    trace!("Private key loaded");

    // Build server config
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS config")?;

    Ok(config)
}

/// Generate a self-signed certificate for testing/development
pub fn generate_self_signed_config() -> Result<ServerConfig> {
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];

    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names)
        .context("Failed to generate self-signed certificate")?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("Failed to serialize private key: {:?}", e))?;

    debug!("Generated self-signed certificate");

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("Failed to build TLS config")?;

    Ok(config)
}
