use actix_files::Files;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer};
use actix_web::{http, web, Responder};
use actix_web::dev::{Server, Service};
use futures_util::{future, FutureExt};
use rustls;
use rustls_pemfile::{certs, pkcs8_private_keys};

use std::{fs::File, io::BufReader};
use std::net::TcpListener;
use rustls::ServerConfig;

const CLIENT_PATH: &str = "/";
const CLIENT_DIR: &str = "./client";
const HTTPS_PORT: u16 = 8443;
const INDEX_FILE: &str = "index.html";

const DEFAULT_VERSION_STRING: &str = "0.0.0";
const DEFAULT_BUILD_NUMBER: &str = "0";

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
                let host = req.connection_info().host().split(":").nth(0).unwrap().to_owned();
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

fn load_rustls_config() -> ServerConfig {
    // init server config builder with safe defaults
    let config = ServerConfig::builder()
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
