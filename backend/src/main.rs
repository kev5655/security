use actix_cors::Cors;
use actix_web::http::header;
use actix_web::middleware::Logger;
use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};

use bincode::config::standard;
use bincode::serde::{decode_from_slice, encode_to_vec};

use tfhe::{ConfigBuilder, generate_keys, set_server_key};

use actix_web::Result;
use serde::Serialize;

use std::sync::Arc;
struct AppState {
    client_key: Arc<tfhe::ClientKey>,
}

#[derive(Serialize)]
struct RegisterResponse {
    client_key: Vec<u8>,
}

#[get("/")]
async fn root() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[get("api/v1/registration")]
async fn registration(data: web::Data<AppState>) -> Result<web::Json<RegisterResponse>> {
    let bytes = encode_to_vec(&*data.client_key, standard())
        .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(web::Json(RegisterResponse { client_key: bytes }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    let app_state = web::Data::new(AppState {
        client_key: Arc::new(client_key),
    });

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
                    .allow_any_header()
                    .supports_credentials()
                    .max_age(3600),
            )
            .app_data(app_state.clone())
            .service(root)
            .service(registration)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
