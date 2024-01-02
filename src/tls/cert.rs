use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use openssl::asn1::Asn1Time;
use openssl::x509::X509;
use rustls_pemfile::certs;

// Load TLS certificates from file
pub fn load_certs<P: AsRef<Path>>(path: P) -> eyre::Result<Vec<rustls::Certificate>> {
    let certs_file = &mut BufReader::new(File::open(path)?);
    let cert_chain = certs(certs_file)
        .unwrap()
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    Ok(cert_chain)
}

pub fn age<P: AsRef<Path>>(path: P) -> eyre::Result<u64> {
    let x509 = X509::from_pem(std::fs::read(path)?.as_slice())?;
    let diff = x509.not_before().diff(Asn1Time::days_from_now(0)?.as_ref())?;
    let age = diff.days as u64 * 86400 + diff.secs as u64;

    Ok(age)
}

pub fn max_age<P: AsRef<Path>>(path: P) -> eyre::Result<u64> {
    let x509 = X509::from_pem(std::fs::read(path)?.as_slice())?;
    let diff = x509.not_before().diff(x509.not_after())?;
    let age = diff.days as u64 * 86400 + diff.secs as u64;

    Ok(age)
}
