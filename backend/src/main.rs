use actix_cors::Cors;
use actix_web::Result;
use actix_web::middleware::Logger;
use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};

// use bincode::{decode_from_slice, encode_to_vec};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::shortint::{Ciphertext, ClientKey, ServerKey, gen_keys};

use bincode::config::standard;
use bincode::serde::{decode_from_slice, encode_to_vec};
use serde::{Deserialize, Serialize};

// use tfhe::{ConfigBuilder, generate_keys, set_server_key};

// use serde::Serialize;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct AppState {
    client_key: Arc<tfhe::shortint::ClientKey>,
    server_key: Arc<tfhe::shortint::ServerKey>,
    vote_data: Mutex<HashMap<i32, Ciphertext>>,
}

#[derive(Serialize)]
struct RegisterResponse {
    client_key: Vec<u8>,
}

#[derive(Deserialize)]
struct VoteRequestPath {
    vote_id: i32,
}

#[derive(Deserialize)]
struct VoteRequest {
    vote: Vec<u8>,
}

#[derive(Serialize)]
struct VoteResponse {
    msg: String,
    result_enc: Vec<u8>,
    result_dec: Vec<u8>,
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

#[post("api/v1/vote/{vote_id}")]
async fn vote(
    data: web::Data<AppState>,
    path: web::Path<VoteRequestPath>,
    vote_payload: web::Json<VoteRequest>,
) -> Result<web::Json<VoteResponse>> {
    let vote_id = path.into_inner().vote_id;
    let vote_vec = vote_payload.into_inner().vote;

    let (vote, _): (Ciphertext, usize) = decode_from_slice::<Ciphertext, _>(&vote_vec, standard())
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let vote_data_arc = &data.vote_data;
    let server_key = &data.server_key;
    let client_key = &data.client_key;

    let current_vote = vote_data_arc
        .lock()
        .map_err(|_| actix_web::error::ErrorInternalServerError("Mutex poisoned"))?
        .get(&vote_id)
        .ok_or_else(|| actix_web::error::ErrorNotFound("Vote ID not found"))?
        .clone();

    let result = server_key.add(&current_vote, &vote);

    data.vote_data
        .lock()
        .map_err(|_| actix_web::error::ErrorInternalServerError("Mutex poisoned"))?
        .insert(vote_id, result.clone());

    let result_enc =
        encode_to_vec(&result, standard()).map_err(actix_web::error::ErrorInternalServerError)?;

    let r_dec = client_key.decrypt(&result);

    let result_dec =
        encode_to_vec(r_dec, standard()).map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(web::Json(VoteResponse {
        msg: "Your have voted".to_string(),
        result_enc: result_enc,
        result_dec: result_dec,
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let (client_key, server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    // set_server_key(server_key);

    let mut start_votes: HashMap<i32, Ciphertext> = HashMap::new();
    let zero = client_key.encrypt(0);
    start_votes.insert(0, zero.clone());
    start_votes.insert(1, zero.clone());

    let app_state = web::Data::new(AppState {
        client_key: Arc::new(client_key),
        server_key: Arc::new(server_key),
        vote_data: Mutex::new(start_votes),
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
            .service(vote)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
