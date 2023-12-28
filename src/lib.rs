use actix_files::Files;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer};
use actix_web::{http, web, Responder};
use actix_web::dev::{Server, Service};
use futures_util::{future, FutureExt};

use std::net::TcpListener;

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
                let url = format!("http://{host}:{HTTPS_PORT}{uri}");

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
    let server = HttpServer::new(|| App::new()
        .route("/status", web::get().to(status))
        .route("/version", web::get().to(version))
        .service(Files::new(CLIENT_PATH, CLIENT_DIR).index_file(INDEX_FILE)))
        .listen(listener)?
        .run();

    Ok(server)
}
