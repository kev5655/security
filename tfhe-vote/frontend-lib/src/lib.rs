mod utils;

use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::Seed;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::shortint::{Ciphertext, ClientKey};
use wasm_bindgen::prelude::*;

use bincode::config::standard;
use bincode::serde::{decode_from_slice, encode_to_vec};

// Optional: console.log from Rust
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

// Optional: better panic messages in the browser
#[cfg(feature = "console_error_panic_hook")]
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

// Export simple functions
#[wasm_bindgen]
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[wasm_bindgen]
pub fn greet(name: &str) -> String {
    format!("Hello, {name} 👋")
}

// Generate a client key from a seed value to match the backend
#[wasm_bindgen]
pub fn generate_client_key_from_seed(seed_value: u128) -> Vec<u8> {
    log(&format!("Generating client key from seed: {}", seed_value));

    // Use the fixed seed for deterministic key generation
    let seed = Seed(seed_value);

    // Create a deterministic seeder with the seed
    let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

    // Generate the client key using the seeder
    let client_key =
        tfhe::shortint::engine::ShortintEngine::new_from_seeder(&mut deterministic_seeder)
            .new_client_key(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    // Serialize the client key for returning to JS
    match encode_to_vec(&client_key, standard()) {
        Ok(serialized) => {
            log("Client key successfully generated and serialized");
            serialized
        }
        Err(e) => {
            log(&format!("Error serializing client key: {:?}", e));
            Vec::new()
        }
    }
}

// Encrypt data using the client key
#[wasm_bindgen]
pub fn encrypt_data(value: u8, serialized_client_key: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    log(&format!("Encrypting value: {}", value));

    // Deserialize the client key
    let client_key: ClientKey = match decode_from_slice(&serialized_client_key, standard()) {
        Ok((key, _)) => key,
        Err(e) => {
            log(&format!("Error deserializing client key: {:?}", e));
            return Err(JsValue::from_str("Failed to deserialize client key"));
        }
    };

    // Encrypt the value
    let ciphertext = client_key.encrypt(value as u64);

    // Serialize the ciphertext
    match encode_to_vec(&ciphertext, standard()) {
        Ok(serialized) => {
            log("Value encrypted and serialized successfully");
            Ok(serialized)
        }
        Err(e) => {
            log(&format!("Error serializing ciphertext: {:?}", e));
            Err(JsValue::from_str("Failed to serialize ciphertext"))
        }
    }
}

// Deserialize and decrypt a ciphertext using the client key
#[wasm_bindgen]
pub fn decrypt_data(
    serialized_ciphertext: Vec<u8>,
    serialized_client_key: Vec<u8>,
) -> Result<u8, JsValue> {
    log("Decrypting data");

    // Deserialize the client key
    let client_key: ClientKey = match decode_from_slice(&serialized_client_key, standard()) {
        Ok((key, _)) => key,
        Err(e) => {
            log(&format!("Error deserializing client key: {:?}", e));
            return Err(JsValue::from_str("Failed to deserialize client key"));
        }
    };

    // Deserialize the ciphertext
    let ciphertext: Ciphertext = match decode_from_slice(&serialized_ciphertext, standard()) {
        Ok((ct, _)) => ct,
        Err(e) => {
            log(&format!("Error deserializing ciphertext: {:?}", e));
            return Err(JsValue::from_str("Failed to deserialize ciphertext"));
        }
    };

    // Decrypt the ciphertext
    let decrypted = client_key.decrypt(&ciphertext) as u8;
    log(&format!("Decrypted value: {}", decrypted));

    Ok(decrypted)
}
