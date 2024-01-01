use actix_files::Files;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer};
use actix_web::{http, web, Responder};
use actix_web::dev::{Server, Service};
use actix_web::middleware::{Logger};
use futures_util::{future, FutureExt};
use rustls_pemfile::{certs, pkcs8_private_keys};

use std::{fs::File, io::BufReader};
use std::net::TcpListener;
use std::time::Duration;

const CLIENT_PATH: &str = "/";
const CLIENT_DIR: &str = "./client";
const HTTPS_PORT: u16 = 8443;
const INDEX_FILE: &str = "index.html";

const DEFAULT_VERSION_STRING: &str = "0.0.0";
const DEFAULT_BUILD_NUMBER: &str = "0";

const CHALLENGE_DIR: &str = "./acme-challenges";
const CERTIFICATE_DIR: &str = "./certs";
const _DOMAIN_NAME: &str = "kodiak.polarlabs.io";
const _CONTACT_EMAIL: &str = "contact@polarlabs.io";

async fn status(_req: HttpRequest) -> impl Responder {
    HttpResponse::Ok()
}

async fn version(_req: HttpRequest) -> impl Responder {
    let version: String = if option_env!("GITHUB_ACTIONS").is_some() {
        format!("{}-{}",
            option_env!("CARGO_PKG_VERSION").unwrap_or(DEFAULT_VERSION_STRING),
            option_env!("BUILD_NUMBER").unwrap_or(DEFAULT_BUILD_NUMBER))
    } else {
        format!("{}-0+local",
            option_env!("CARGO_PKG_VERSION").unwrap_or(DEFAULT_VERSION_STRING))
    };

    println!("{}", version);

    HttpResponse::Ok()
}

async fn redirect_to_https(_req: HttpRequest) -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain")
        .body("Kodiak: hey, always use HTTPS!")
}

// https://github.com/actix/examples/tree/master/middleware/http-to-https
pub fn run_http(listener: TcpListener) -> Result<Server, std::io::Error> {
    let server = HttpServer::new(|| App::new()
        .wrap_fn(|req, srv| {
            if req.connection_info().scheme() == "https" {
                future::Either::Left(srv.call(req).map(|res| res))
            } else {
                let host = req.connection_info().host().split(':').next().unwrap().to_owned();
                let uri = req.uri().to_owned();
                let url = format!("https://{host}:{HTTPS_PORT}{uri}");

                future::Either::Right(future::ready(Ok(req.into_response(
                    HttpResponse::MovedPermanently()
                        .append_header((http::header::LOCATION, url))
                        .finish(),
                ))))
            }
        })
        .route("/", web::get().to(redirect_to_https)))
        .listen(listener)?
        .run();

    Ok(server)
}

pub fn run_https(listener: TcpListener) -> Result<Server, std::io::Error> {
    let tls_config = load_rustls_config();

    let server = HttpServer::new(|| App::new()
        .route("/status", web::get().to(status))
        .route("/version", web::get().to(version))
        .service(Files::new(CLIENT_PATH, CLIENT_DIR).index_file(INDEX_FILE)))
        .listen_rustls_0_21(listener, tls_config)?
        .run();

    Ok(server)
}

fn load_rustls_config() -> rustls::ServerConfig {
    // init server config builder with safe defaults
    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    // load TLS key/cert files
    let cert_file = &mut BufReader::new(File::open("cert.pem").unwrap());
    let key_file = &mut BufReader::new(File::open("key.pem").unwrap());

    // convert files to key/cert objects
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(rustls::Certificate)
        .collect();
    let mut keys: Vec<rustls::PrivateKey> = pkcs8_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(rustls::PrivateKey)
        .collect();

    // convert files to key/cert objects (rustls 0.22.x + rustls-pemfile 2.0.0)
    //let cert_chain: Vec<CertificateDer> = certs(cert_file).map(|x| x.unwrap()).collect();
    //let mut keys: Vec<PrivatePkcs8KeyDer> = pkcs8_private_keys(key_file).map(|x| x.unwrap()).collect();

    // exit if no keys could be parsed
    if keys.is_empty() {
        eprintln!("Could not locate PKCS 8 private keys.");
        std::process::exit(1);
    }

    config.with_single_cert(cert_chain, keys.remove(0)).unwrap()
    //config.with_single_cert(cert_chain, PrivateKeyDer::from(keys.remove(0))).unwrap()
}

pub async fn gen_tls_cert(listener: TcpListener, user_domain: &str, contact_email: &str) -> eyre::Result<acme::Certificate> {
    // Create directory for ACME challenge.
    log::info!("Ensure directory for ACME challenge exists.");
    tokio::fs::create_dir_all(CHALLENGE_DIR).await?;

    // Create directory for keys & certificates.
    log::info!("Ensure directory for keys & certificates exists.");
    tokio::fs::create_dir_all(CERTIFICATE_DIR).await?;

    // Start temporary HTTP server to handle ACME challenge.
    log::info!("Start HTTP server to handle ACME challenge.");
    let server = HttpServer::new(|| {
        App::new()
            .wrap(Logger::default().log_target("acme"))
            .service(
                Files::new("/.well-known/acme-challenge", CHALLENGE_DIR).show_files_listing(),
        )
    })
        .listen(listener)?
        .workers(1)
        .shutdown_timeout(0)
        .disable_signals()
        .run();

    let server_handle = server.handle();
    let server_task = tokio::spawn(server);

    // Use DirectoryUrl::LetsEncryptStaging for dev/testing.
    //let url = acme::DirectoryUrl::LetsEncrypt;
    let url = acme::DirectoryUrl::LetsEncryptStaging;

    // Create a directory entrypoint.
    let dir = acme::Directory::fetch(url).await?;

    // Our contact addresses; note the `mailto:`
    let user_email_mailto = format!("mailto:{contact_email}");
    let contact = vec![user_email_mailto];

    // Generate a private key and register an account with our ACME provider.
    // We should write it to disk any use `load_account` afterwards.
    // https://github.com/x52dev/acme-rfc8555/blob/main/examples/http-01.rs
    let account = dir.register_account(Some(contact.clone())).await?;

    // Load an account from string
    let priv_key = account.acme_private_key_pem()?;
    let account = dir.load_account(&priv_key, Some(contact)).await?;

    // Order a new TLS certificate for the domain.
    let mut new_order = account.new_order(user_domain, &[]).await?;

    // If the ownership of the domain has already been proven
    // in a previous order, we might be able to
    // skip validation. The ACME API provider decides.
    let csr_order = loop {
        // Are we done?
        if let Some(csr_order) = new_order.confirm_validations() {
            break csr_order;
        }

        // Get the possible authorizations (for a single domain
        // this will only be one element).
        let auths = new_order.authorizations().await?;

        // For HTTP, the challenge is a text file that needs to be placed so it
        // is accessible to our web server:
        //
        // ./acme-challenge/<token>
        //
        // The important thing is that it's accessible over the
        // web for the domain we are trying to get a
        // certificate for:
        //
        // http://example.org/.well-known/acme-challenge/<token>
        let challenge = auths[0]
            .http_challenge()
            .expect("HTTP challenge not accessible");

        // The token is the filename.
        let token = challenge.http_token();

        // The proof is the contents of the file
        let proof = challenge.http_proof()?;

        // Place the file/contents in the correct place.
        let path = format!("{CHALLENGE_DIR}/{token}");
        tokio::fs::write(&path, &proof).await?;

        // After the file is accessible from the web
        // tell the ACME API to start checking the
        // existence of the proof.
        //
        // The order at ACME will change status to either
        // confirm ownership of the domain, or fail due to the
        // not finding the proof. To see the change, we poll
        // the API with 5000 milliseconds wait between.
        challenge.validate(Duration::from_millis(5000)).await?;

        // Update the state against the ACME API.
        new_order.refresh().await?;
    };

    // Ownership is proven. Create a private key for
    // the certificate. These are provided for convenience; we
    // could provide our own keypair instead if we want.
    let signing_key = acme::create_p256_key();

    // Submit the CSR. This causes the ACME provider to enter a
    // state of "processing" that must be polled until the
    // certificate is either issued or rejected. Again we poll
    // for the status change.
    let cert_order = csr_order
        .finalize(signing_key, Duration::from_millis(5000))
        .await.unwrap();

    // Download the certificate.
    let cert = cert_order.download_cert().await.unwrap();

    // Stop temporary server for ACME challenge
    server_handle.stop(true).await;
    server_task.await??;

    // Delete acme-challenge dir
    tokio::fs::remove_dir_all(CHALLENGE_DIR).await?;

    log::info!("Persist certificate.");
    let cert_path = format!("{CERTIFICATE_DIR}/{user_domain}.pem");
    tokio::fs::write(&cert_path, cert.certificate()).await?;
    log::info!("Certificate persisted to {cert_path}.");

    // todo: ensure strict access rights on file
    log::info!("Persist key.");
    let key_path = format!("{CERTIFICATE_DIR}/{user_domain}.key");
    tokio::fs::write(&key_path, cert.private_key()).await?;
    log::info!("Private key persisted to {key_path}.");

    Ok(cert)
}

pub fn cert_remaining_validity() -> u32 {
    42
}
