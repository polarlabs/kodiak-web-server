use actix_files::Files;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer};
use actix_web::{web, Responder};
use actix_web::dev::Server;

const CLIENT_PATH: &str = "/";
const INTERFACE: &str = "0.0.0.0"; // Binds to all interfaces.
const PORT: u16 = 8080;
const CLIENT_DIR: &str = "./client";
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

pub fn run() -> Result<Server, std::io::Error> {
    let server = HttpServer::new(|| App::new()
        .route("/status", web::get().to(status))
        .route("/version", web::get().to(version))
        .service(Files::new(CLIENT_PATH, CLIENT_DIR).index_file(INDEX_FILE)))
        .bind((INTERFACE, PORT))?
        .run();

    Ok(server)
}
