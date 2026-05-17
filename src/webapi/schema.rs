use crate::db;
use crate::db::Pool;
use crate::model;

use actix_web::guard::All;
use actix_web::http::header::Header;
use actix_web::{delete, get, guard, post, put, web, HttpResponse, Responder};
use chrono::Utc;
use serde::Deserialize;
use validator::Validate;

#[derive(Deserialize, Validate, Debug)]
pub struct SchemaCreateReq {
    #[validate(length(min = 5, message = "Name must be greater than 5 chars"))]
    name: String,
}

impl SchemaCreateReq {
    pub fn name(&self) -> &String {
        &self.name
    }
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/webapi/v1/_kodiak")
            .service(
                web::resource("/schemas")
                    .guard(guard::Post())
                    .guard(guard::Header("content-type", "application/json"))
                    .route(web::post().to(create)),
            )
            .route(
                "/schemas",
                web::route()
                    .guard(guard::Post())
                    .guard(guard::Not(guard::Header(
                        "content-type",
                        "application/json",
                    )))
                    .to(HttpResponse::UnsupportedMediaType),
            )
            .service(read)
            .service(update)
            .service(delete)
            .default_service(web::route().to(HttpResponse::MethodNotAllowed)),
    )
    .service(
        web::scope("/webapi/v1").service(
            web::resource("/{schema}")
                .guard(guard::Get())
                .route(web::get().to(read_schema)),
        ),
    );
}

async fn create(req: web::Json<SchemaCreateReq>, pool: web::Data<Pool>) -> impl Responder {
    let timestamp = Utc::now().to_rfc3339();
    log::debug!(
        "Received POST to /schemas API endpoint on {}. Data: {:?}",
        timestamp,
        req
    );

    let is_valid = req.validate();
    match is_valid {
        Ok(_) => {
            let schema = model::Schema::from(req.into_inner());

            if let Ok(result) = db::schema::select_one_by_name(pool.get_ref(), schema.name()).await
            {
                // Schema exists (identifier: "name")?
                match result {
                    None => {
                        let schema: db::Schema = schema.try_into().unwrap();
                        let result = db::create_schema(pool.get_ref(), schema).await;

                        // todo: error handling

                        log::info!("Result of insert: {:?}", result);
                        HttpResponse::Created().body("Schema created successfully!")
                    }
                    Some(_) => HttpResponse::Conflict().body("Schema already exists."),
                }
            } else {
                HttpResponse::InternalServerError().body("Connection to database failed.")
            }
        }
        Err(err) => HttpResponse::BadRequest().json(err),
    }

    //
    // Flow:
    //
    // Schema exists?
    // yes:
    //   HttpResponse::Conflict().body("Schema already exists.")
    // no:
    //   INSERT schema in _kodiak database
    //   ATTACH schema as dedicated fs
    //   Return HttpResponse::Created()

    // todo
    // Create table in _kodiak to manage schemas (part of 0.2.0)
    // id, name, fs, tstamp_created, tstamp_updated
    // use chrono feature of sqlx, in rust use chrono::DateTime<chrono::Utc>
    // Set Location Hedaer to point to created schema /schema/{uuid}
    // https://restfulapi.net/rest-put-vs-post/
}

#[get("/schemas")]
async fn read() -> impl Responder {
    log::info!("Get schema received.");
    HttpResponse::Ok().body("Schemas listed.")
}

#[put("/schemas")]
async fn update() -> impl Responder {
    HttpResponse::Ok().body("Schema updated successfully!")
}

#[delete("/schemas")]
async fn delete() -> impl Responder {
    HttpResponse::NoContent().finish()
}

async fn read_schema(schema: web::Path<String>, pool: web::Data<Pool>) -> impl Responder {
    log::info!("Get read schema {} received.", schema);
    HttpResponse::Ok().body("This is the detailed information about this schema.")
}
