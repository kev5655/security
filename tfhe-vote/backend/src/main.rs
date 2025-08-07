use actix_cors::Cors;
use actix_web::Result;
use actix_web::middleware::Logger;
use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};

use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::Seed;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;
use tfhe::shortint::Ciphertext;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bincode::config::standard;
use bincode::serde::encode_to_vec;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct AppState {
    client_key: Arc<tfhe::shortint::ClientKey>,
    server_key: Arc<tfhe::shortint::ServerKey>,
    vote_data: Mutex<HashMap<i32, Ciphertext>>,
}

#[derive(Serialize)]
struct RegisterResponse {
    seed: u128,
}

#[derive(Deserialize, Debug)]
struct VoteRequestPath {
    vote_id: i32,
}

#[derive(Deserialize, Debug)]
struct VoteRequest {
    vote: Vec<u8>, // Base64 encoded serialized ciphertext
}

#[derive(Serialize)]
struct VoteResponse {
    msg: String,
    result_enc: String, // Base64 encoded string of serialized ciphertext
    result_dec: Vec<u8>,
}

#[get("/")]
async fn root() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[get("api/v1/registration")]
async fn registration(_data: web::Data<AppState>) -> Result<web::Json<RegisterResponse>> {
    // Instead of sending the serialized client key, we send the seed value
    // that was used to generate the key
    // We use the same seed for both backend and frontend
    // This is a fixed seed - in production you might want to use a session-specific seed

    let seed_value = 12345678901234567890;

    Ok(web::Json(RegisterResponse { seed: seed_value }))
}

#[post("api/v1/vote/{vote_id}")]
async fn vote(
    data: web::Data<AppState>,
    path: web::Path<VoteRequestPath>,
    vote_payload: web::Json<VoteRequest>,
) -> Result<web::Json<VoteResponse>> {
    let vote_id = path.into_inner().vote_id;
    println!("Extracting vote data for ID: {}", vote_id);
    let payload = vote_payload.into_inner();
    let vec8_vote = payload.vote;

    // Get references to application state
    let client_key = &data.client_key;
    let server_key = &data.server_key;
    let vote_data_mutex = &data.vote_data;

    println!("Processing vote for ID: {}", vote_id);
    println!(
        "First 10 bytes of received vote data: {:?}",
        vec8_vote.iter().take(10).collect::<Vec<_>>()
    );

    let vote_ciphertext = process_vote_data(vec8_vote)?;

    println!("Retrieving current vote for ID: {}", vote_id);
    let current_vote = get_current_vote(vote_data_mutex, vote_id)?;

    println!("Adding new vote to current tally for ID: {}", vote_id);
    let result = server_key.add(&current_vote, &vote_ciphertext);

    // Update the vote data in storage
    update_vote_data(vote_data_mutex, vote_id, result.clone())?;

    // Prepare the response with encrypted and decrypted results
    let result_enc = serialize_result(&result)?;
    let result_dec = vec![client_key.decrypt(&result) as u8];

    Ok(web::Json(VoteResponse {
        msg: "Your vote has been counted".to_string(),
        result_enc,
        result_dec,
    }))
}

// Helper function to process the vote data from the request
fn process_vote_data(vec8_vote: Vec<u8>) -> Result<Ciphertext> {
    // Try to deserialize the ciphertext
    println!("Processing raw vote data with length: {}", vec8_vote.len());

    // Deserialize using bincode
    let deserialization_result =
        bincode::serde::decode_from_slice::<Ciphertext, _>(&vec8_vote, standard());

    // Get the ciphertext or return an error if deserialization fails
    match deserialization_result {
        Ok((ciphertext, _)) => {
            println!("Deserialization successful!");
            Ok(ciphertext)
        }
        Err(e) => {
            println!("Deserialization error: {:?}", e);
            Err(actix_web::error::ErrorBadRequest(format!(
                "Deserialization error: {:?}",
                e
            )))
        }
    }
}

// Helper function to get the current vote count
fn get_current_vote(
    vote_data_mutex: &Mutex<HashMap<i32, Ciphertext>>,
    vote_id: i32,
) -> Result<Ciphertext> {
    vote_data_mutex
        .lock()
        .map_err(|_| actix_web::error::ErrorInternalServerError("Mutex poisoned"))?
        .get(&vote_id)
        .ok_or_else(|| actix_web::error::ErrorNotFound("Vote ID not found"))
        .map(|v| v.clone())
}

// Helper function to update the vote data
fn update_vote_data(
    vote_data_mutex: &Mutex<HashMap<i32, Ciphertext>>,
    vote_id: i32,
    result: Ciphertext,
) -> Result<()> {
    vote_data_mutex
        .lock()
        .map_err(|_| actix_web::error::ErrorInternalServerError("Mutex poisoned"))?
        .insert(vote_id, result);

    Ok(())
}

// Helper function to serialize the result
fn serialize_result(result: &Ciphertext) -> Result<String> {
    match encode_to_vec(result, standard()) {
        Ok(encoded) => {
            // Convert to base64 for JSON transport
            Ok(BASE64.encode(&encoded))
        }
        Err(e) => Err(actix_web::error::ErrorInternalServerError(format!(
            "Serialization error: {:?}",
            e
        ))),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting TFHE voting server...");

    // Use a fixed seed for deterministic key generation
    // This should match the seed sent to the frontend
    let seed_value = 12345678901234567890;
    let seed = Seed(seed_value);

    // Create a deterministic seeder with the seed
    let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

    // Generate the client key using the seeder
    let client_key =
        tfhe::shortint::engine::ShortintEngine::new_from_seeder(&mut deterministic_seeder)
            .new_client_key(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    // Generate the server key from the client key
    let server_key = tfhe::shortint::ServerKey::new(&client_key);

    let mut start_votes: HashMap<i32, Ciphertext> = HashMap::new();
    let zero = client_key.encrypt(0);
    start_votes.insert(0, zero.clone());
    start_votes.insert(1, zero.clone());

    let app_state = web::Data::new(AppState {
        client_key: Arc::new(client_key),
        server_key: Arc::new(server_key),
        vote_data: Mutex::new(start_votes),
    });

    print!("Server is ready\n");

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

    // Server will run until interrupted
}
