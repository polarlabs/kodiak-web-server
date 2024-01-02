use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use rustls_pemfile::pkcs8_private_keys;

// Load TLS key from file
pub fn load_key<P: AsRef<Path>>(path: P) -> eyre::Result<Option<rustls::PrivateKey>> {
    let key_file = &mut BufReader::new(File::open(path)?);
    let key = pkcs8_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(rustls::PrivateKey)
        .next();

    Ok(key)
}
