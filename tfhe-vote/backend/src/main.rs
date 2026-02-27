use actix_cors::Cors;
use actix_web::Result;
use actix_web::middleware::Logger;
use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};

use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::Seed;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;
use tfhe::shortint::Ciphertext;
use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bincode::config::standard;
use bincode::serde::encode_to_vec;
use serde::{Deserialize, Serialize};
use tfhe::{ClientKey, ConfigBuilder};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct AppState {
    client_key: Arc<tfhe::shortint::ClientKey>,
    server_key: Arc<tfhe::shortint::ServerKey>,
    vote_data: Mutex<HashMap<i32, Ciphertext>>,
}

#[derive(Serialize)]
struct RegisterResponse {
    seed: String,
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

    let seed_value = "12345678901234567890".to_string();

    Ok(web::Json(RegisterResponse { seed: seed_value }))
}

#[post("api/v1/vote/{vote_id}")]
async fn vote(
    data: web::Data<AppState>,
    path: web::Path<VoteRequestPath>,
    vote_payload: web::Json<VoteRequest>,
) -> Result<web::Json<VoteResponse>> {
    let vote_id = path.into_inner().vote_id;
    println!("[DEBUG] Extracting vote data for ID: {}", vote_id);
    let payload = vote_payload.into_inner();
    let vec8_vote = payload.vote;

    // Get references to application state
    let client_key = &data.client_key;
    let server_key = &data.server_key;
    let vote_data_mutex = &data.vote_data;

    println!("[DEBUG] Processing vote for ID: {}", vote_id);
    println!(
        "[DEBUG] Vote data length: {}, First 10 bytes: {:?}",
        vec8_vote.len(),
        vec8_vote.iter().take(10).collect::<Vec<_>>()
    );

    let vote_ciphertext = process_vote_data(vec8_vote)?;

    println!("[DEBUG] Retrieving current vote for ID: {}", vote_id);
    let current_vote = get_current_vote(vote_data_mutex, vote_id)?;

    let vote_value = client_key.decrypt(&vote_ciphertext) as u8;
    let current_count = client_key.decrypt(&current_vote) as u8;

    println!(
        "[DEBUG] Vote from frontend: {} (raw u64: {})",
        vote_value,
        client_key.decrypt(&vote_ciphertext)
    );
    println!(
        "[DEBUG] Current vote count for ID {}: {} (raw u64: {})",
        vote_id,
        current_count,
        client_key.decrypt(&current_vote)
    );

    println!(
        "[DEBUG] Adding new vote ({}) to current tally ({}) for ID: {}",
        vote_value, current_count, vote_id
    );

    // Perform the addition operation
    let result = server_key.add(&current_vote, &vote_ciphertext);

    let new_count = client_key.decrypt(&result) as u8;
    println!(
        "[DEBUG] New vote count for ID {}: {} (raw u64: {})",
        vote_id,
        new_count,
        client_key.decrypt(&result)
    );

    // Verify the math
    println!(
        "[DEBUG] Verification: {} + {} should equal {} (actual: {})",
        current_count,
        vote_value,
        current_count + vote_value,
        new_count
    );

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
    println!(
        "[DEBUG] Processing raw vote data with length: {}",
        vec8_vote.len()
    );
    println!(
        "[DEBUG] First 20 bytes: {:?}",
        vec8_vote.iter().take(20).collect::<Vec<_>>()
    );
    println!(
        "[DEBUG] Last 20 bytes: {:?}",
        vec8_vote.iter().rev().take(20).collect::<Vec<_>>()
    );

    // Deserialize using bincode
    let deserialization_result =
        bincode::serde::decode_from_slice::<Ciphertext, _>(&vec8_vote, standard());

    // Get the ciphertext or return an error if deserialization fails
    match deserialization_result {
        Ok((ciphertext, _)) => {
            println!("[DEBUG] Deserialization successful!");
            Ok(ciphertext)
        }
        Err(e) => {
            println!("[DEBUG] Deserialization error: {:?}", e);
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
    println!("[DEBUG] Using seed value: {}", seed_value);
    let seed = Seed(seed_value);

    // Create a deterministic seeder with the seed
    let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
    let config = ConfigBuilder::default().build();

    // Generate the client key using the seed directly
    println!("[DEBUG] Generating client key from seed");
    // Use shortint-specific key generation
    let client_key =
        tfhe::shortint::engine::ShortintEngine::new_from_seeder(&mut deterministic_seeder)
            .new_client_key(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    // Test the client key by encrypting and decrypting values within and outside the supported range
    let test_values = [0u8, 1, 2, 3, 255];
    println!("[DEBUG] Testing client key with various values:");
    for &val in &test_values {
        let encrypted = client_key.encrypt(val as u64);
        let decrypted = client_key.decrypt(&encrypted) as u8;
        println!(
            "[DEBUG] Test encrypt/decrypt: {} -> {} (should be {})",
            val, decrypted, val
        );

        // Check if the decryption worked correctly
        if val != decrypted {
            if val > 3 {
                println!(
                    "[DEBUG] Expected failure: Value {} exceeds the 2-bit message space (0-3)",
                    val
                );
            } else {
                println!(
                    "[DEBUG] WARNING: Encryption verification failed for value {}!",
                    val
                );
            }
        }
    }

    // Generate the server key from the client key
    println!("[DEBUG] Generating server key");
    let server_key = tfhe::shortint::ServerKey::new(&client_key);

    // Test homomorphic addition within bounds
    println!("[DEBUG] Testing homomorphic addition within bounds");
    let a = 1u8;
    let b = 2u8;
    let cipher_a = client_key.encrypt(a as u64);
    let cipher_b = client_key.encrypt(b as u64);
    let cipher_sum = server_key.add(&cipher_a, &cipher_b);
    let decrypted_sum = client_key.decrypt(&cipher_sum) as u8;
    println!(
        "[DEBUG] Homomorphic addition (within bounds): {} + {} = {} (decrypted: {})",
        a,
        b,
        a + b,
        decrypted_sum
    );

    // Test homomorphic addition that exceeds bounds (2+3=5 > 3)
    println!("[DEBUG] Testing homomorphic addition that exceeds bounds");
    let a = 2u8;
    let b = 3u8;
    let cipher_a = client_key.encrypt(a as u64);
    let cipher_b = client_key.encrypt(b as u64);
    let cipher_sum = server_key.add(&cipher_a, &cipher_b);
    let decrypted_sum = client_key.decrypt(&cipher_sum) as u8;
    println!(
        "[DEBUG] Homomorphic addition (overflow): {} + {} = {} (decrypted: {} - OVERFLOW)",
        a,
        b,
        a + b,
        decrypted_sum
    );
    println!(
        "[DEBUG] NOTE: The overflow is expected with PARAM_MESSAGE_2_CARRY_2_KS_PBS when result > 3"
    );

    // Initialize vote data
    println!("[DEBUG] Initializing vote data with zeros");
    let mut start_votes: HashMap<i32, Ciphertext> = HashMap::new();
    let zero = client_key.encrypt(0);

    // Verify the zero value
    let zero_check = client_key.decrypt(&zero) as u8;
    println!(
        "[DEBUG] Zero ciphertext decryption check: {} (should be 0)",
        zero_check
    );

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
