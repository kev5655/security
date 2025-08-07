use actix_cors::Cors;
use actix_web::Result;
use actix_web::middleware::Logger;
use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};

// use bincode::{decode_from_slice, encode_to_vec};
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::Seed;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;
use tfhe::shortint::Ciphertext;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bincode::config::standard;
use bincode::serde::{decode_from_slice, encode_to_vec};
use serde::{Deserialize, Serialize};

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
    seed: u128,
}

#[derive(Deserialize, Debug)]
struct VoteRequestPath {
    vote_id: i32,
}

#[derive(Deserialize, Debug)]
struct VoteMetadata {
    original_length: usize,
    first_bytes: Vec<u8>,
    #[serde(default)]
    diagnose_mode: bool,
    #[serde(default)]
    raw_value: u8,
}

#[derive(Deserialize, Debug)]
struct VoteRequest {
    vote: String, // Base64 encoded serialized ciphertext
    metadata: VoteMetadata,
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
    println!("Registration endpoint called. Sending seed: {}", seed_value);

    Ok(web::Json(RegisterResponse { seed: seed_value }))
}

#[post("api/v1/vote/{vote_id}")]
async fn vote(
    data: web::Data<AppState>,
    path: web::Path<VoteRequestPath>,
    vote_payload: web::Json<VoteRequest>,
) -> Result<web::Json<VoteResponse>> {
    println!("Vote endpoint handler called - starting processing");
    println!("Raw payload received: {:?}", vote_payload);
    let vote_id = path.into_inner().vote_id;
    let payload = vote_payload.into_inner();
    let base64_vote = payload.vote;
    let metadata = payload.metadata;

    println!("Vote endpoint called for vote_id: {}", vote_id);
    println!("Received base64 vote of length: {}", base64_vote.len());
    println!("Original binary length: {}", metadata.original_length);
    println!("First bytes: {:?}", metadata.first_bytes);

    // Decode base64 to binary
    let vote_vec = match BASE64.decode(base64_vote) {
        Ok(data) => {
            println!(
                "Successfully decoded base64. Binary size: {} bytes",
                data.len()
            );
            println!("First 8 bytes: {:?}", &data[..std::cmp::min(8, data.len())]);
            data
        }
        Err(e) => {
            println!("Base64 decoding error: {:?}", e);
            return Err(actix_web::error::ErrorInternalServerError(format!(
                "Base64 decoding error: {:?}",
                e
            )));
        }
    };

    // Add detailed logging of binary data for debugging
    println!("Binary data (first 32 bytes):");
    for (i, chunk) in vote_vec.chunks(8).take(4).enumerate() {
        println!("  Bytes {}-{}: {:?}", i * 8, i * 8 + chunk.len() - 1, chunk);
    }

    // Try to deserialize with detailed error handling
    println!("Attempting to deserialize with bincode...");

    // Debug the actual binary data vs what we expect
    println!("Binary data format check:");
    if vote_vec.len() > 0 {
        println!("  First byte: {}", vote_vec[0]); // Version or format indicator?
    }
    if vote_vec.len() > 8 {
        let header_bytes = &vote_vec[0..8];
        println!("  Header bytes: {:?}", header_bytes);

        // Try to interpret the header in different ways
        if header_bytes.len() >= 8 {
            let as_u64_bytes = [
                header_bytes[0],
                header_bytes[1],
                header_bytes[2],
                header_bytes[3],
                header_bytes[4],
                header_bytes[5],
                header_bytes[6],
                header_bytes[7],
            ];
            let as_u64 = u64::from_le_bytes(as_u64_bytes);
            println!("  As u64 (little endian): {}", as_u64);

            let as_u64_be = u64::from_be_bytes(as_u64_bytes);
            println!("  As u64 (big endian): {}", as_u64_be);
        }
    }

    // First, try standard bincode deserialization
    println!("Trying standard bincode deserialization...");
    let deserialization_result =
        bincode::serde::decode_from_slice::<Ciphertext, _>(&vote_vec, standard());
    match &deserialization_result {
        Ok((_, bytes_consumed)) => {
            println!(
                "Successfully deserialized! Consumed {} bytes out of {}",
                bytes_consumed,
                vote_vec.len()
            );
        }
        Err(e) => {
            println!("Deserialization error details: {:?}", e);
            println!("Error type: {}", std::any::type_name_of_val(e));

            // Try to get more context about the error
            match e {
                bincode::error::DecodeError::Other(msg) => {
                    println!("Other error: {}", msg);
                }
                _ => {
                    println!("Non-'Other' error type");
                }
            }

            // Continue with error - we'll return it below
        }
    }

    // Get the ciphertext or try diagnostic mode if deserialization fails
    let vote = match deserialization_result {
        Ok((ciphertext, _)) => {
            println!("Successfully got ciphertext from deserialization");
            ciphertext
        }
        Err(e) => {
            // Let's try to identify specific issues
            println!("CRITICAL ERROR: Failed to deserialize ciphertext: {:?}", e);

            // Check if we're in diagnostic mode
            if metadata.diagnose_mode {
                println!("DIAGNOSTIC MODE ACTIVE - Using raw value instead");
                println!("Creating ciphertext from raw value: {}", metadata.raw_value);

                // Create a new ciphertext from the raw value using the client key
                let client_key = &data.client_key;
                let diagnostic_ciphertext = client_key.encrypt(metadata.raw_value as u64);

                println!("Created diagnostic ciphertext");
                diagnostic_ciphertext
            } else {
                // Provide detailed error information
                let error_msg = format!(
                    "Deserialization error. Details: {:?}. Binary size: {}. First 16 bytes: {:?}",
                    e,
                    vote_vec.len(),
                    &vote_vec[..std::cmp::min(16, vote_vec.len())]
                );

                // Return a 400 Bad Request with detailed error info
                return Err(actix_web::error::ErrorBadRequest(error_msg));
            }
        }
    };

    let vote_data_arc = &data.vote_data;
    let server_key = &data.server_key;
    let client_key = &data.client_key;

    let current_vote = vote_data_arc
        .lock()
        .map_err(|_| actix_web::error::ErrorInternalServerError("Mutex poisoned"))?
        .get(&vote_id)
        .ok_or_else(|| actix_web::error::ErrorNotFound("Vote ID not found"))?
        .clone();

    println!("Adding vote to current tally for vote_id: {}", vote_id);
    let result = server_key.add(&current_vote, &vote);

    data.vote_data
        .lock()
        .map_err(|_| actix_web::error::ErrorInternalServerError("Mutex poisoned"))?
        .insert(vote_id, result.clone());

    // Use bincode for serialization of the result
    let result_enc = match encode_to_vec(&result, standard()) {
        Ok(encoded) => {
            println!(
                "Successfully serialized result. Size: {} bytes",
                encoded.len()
            );
            // Convert to base64 for JSON transport
            let base64_result = BASE64.encode(&encoded);
            println!("Base64 encoded result. Size: {} chars", base64_result.len());
            base64_result
        }
        Err(e) => {
            println!("Serialization error: {:?}", e);
            return Err(actix_web::error::ErrorInternalServerError(format!(
                "Serialization error: {:?}",
                e
            )));
        }
    };

    println!("Decrypting result");
    let r_dec = client_key.decrypt(&result);
    println!("Decrypted result: {}", r_dec);

    // For result_dec, just use a simple JSON-serializable representation
    let result_dec = vec![r_dec as u8];

    println!("Vote processing completed. Sending response.");
    Ok(web::Json(VoteResponse {
        msg: "Your vote has been counted".to_string(),
        result_enc: result_enc,
        result_dec: result_dec,
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting TFHE voting server...");

    // Use a fixed seed for deterministic key generation
    // This should match the seed sent to the frontend
    let seed_value = 12345678901234567890;
    println!("Using seed value: {}", seed_value);
    let seed = Seed(seed_value);

    // Create a deterministic seeder with the seed
    let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

    println!("Generating client key...");
    // Generate the client key using the seeder
    let client_key =
        tfhe::shortint::engine::ShortintEngine::new_from_seeder(&mut deterministic_seeder)
            .new_client_key(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    println!("Client key generated");

    println!("Generating server key...");
    // Generate the server key from the client key
    let server_key = tfhe::shortint::ServerKey::new(&client_key);
    println!("Server key generated");

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

    // Server will run until interrupted
}
