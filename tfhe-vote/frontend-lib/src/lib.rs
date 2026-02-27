mod utils;

use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::Seed;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;
use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
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
    log(&format!(
        "[DEBUG] Generating client key from seed: {}",
        seed_value
    ));

    // Check if the seed matches what we expect from the backend
    const EXPECTED_SEED: u128 = 12345678901234567890;
    if seed_value != EXPECTED_SEED {
        log(&format!(
            "[DEBUG] Warning: Seed value mismatch! Expected: {}, Got: {}",
            EXPECTED_SEED, seed_value
        ));
    } else {
        log("[DEBUG] Seed value matches expected backend value");
    }

    // Use the fixed seed for deterministic key generation
    let seed = Seed(seed_value);

    // Create a deterministic seeder with the seed
    let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

    // Generate the client key using the seeder
    let client_key =
        tfhe::shortint::engine::ShortintEngine::new_from_seeder(&mut deterministic_seeder)
            .new_client_key(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    // Test the client key by encrypting and decrypting a test value
    let test_value = 42u8;
    let test_ciphertext = client_key.encrypt(test_value as u64);
    let test_decrypted = client_key.decrypt(&test_ciphertext) as u8;
    log(&format!(
        "[DEBUG] Client key test - Encrypted {} and decrypted {}",
        test_value, test_decrypted
    ));

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

    // Check for overflow - we're using PARAM_MESSAGE_8 so 0-255 (8-bit) values are supported
    if value > 255 {
        log(&format!(
            "[ERROR] Value {} exceeds the supported range (0-255)",
            value
        ));
        return Err(JsValue::from_str(&format!(
            "Value {} exceeds the supported range (0-255)",
            value
        )));
    }

    log(&format!(
        "[DEBUG] Client key serialized size: {} bytes",
        serialized_client_key.len()
    ));

    // Deserialize the client key
    let client_key: ClientKey = match decode_from_slice(&serialized_client_key, standard()) {
        Ok((key, _)) => key,
        Err(e) => {
            log(&format!("[DEBUG] Error deserializing client key: {:?}", e));
            return Err(JsValue::from_str(&format!(
                "Failed to deserialize client key: {:?}",
                e
            )));
        }
    };

    // Encrypt the value
    log(&format!(
        "[DEBUG] Encrypting {} as u64: {}",
        value, value as u64
    ));
    let ciphertext = client_key.encrypt(value as u64);
    let decrypted_check = client_key.decrypt(&ciphertext) as u8;
    log(&format!(
        "[DEBUG] Encryption verification - Original: {}, Decrypted: {}, Raw u64: {}",
        value,
        decrypted_check,
        client_key.decrypt(&ciphertext)
    ));

    if value != decrypted_check {
        log(&format!(
            "[DEBUG] WARNING: Encryption verification failed! Original: {}, Decrypted: {}",
            value, decrypted_check
        ));
    }

    // Serialize the ciphertext
    match encode_to_vec(&ciphertext, standard()) {
        Ok(serialized) => {
            log(&format!(
                "[DEBUG] Ciphertext serialized successfully, size: {} bytes",
                serialized.len()
            ));
            log(&format!(
                "[DEBUG] First 20 bytes of serialized ciphertext: {:?}",
                serialized.iter().take(20).collect::<Vec<_>>()
            ));
            Ok(serialized)
        }
        Err(e) => {
            log(&format!("[DEBUG] Error serializing ciphertext: {:?}", e));
            Err(JsValue::from_str(&format!(
                "Failed to serialize ciphertext: {:?}",
                e
            )))
        }
    }
}

// Deserialize and decrypt a ciphertext using the client key
#[wasm_bindgen]
pub fn decrypt_data(
    serialized_ciphertext: Vec<u8>,
    serialized_client_key: Vec<u8>,
) -> Result<u8, JsValue> {
    log("[DEBUG] Decrypting data");
    log(&format!(
        "[DEBUG] Serialized ciphertext size: {} bytes",
        serialized_ciphertext.len()
    ));
    log(&format!(
        "[DEBUG] Client key serialized size: {} bytes",
        serialized_client_key.len()
    ));

    log(&format!(
        "[DEBUG] First 20 bytes of serialized ciphertext: {:?}",
        serialized_ciphertext.iter().take(20).collect::<Vec<_>>()
    ));
    log(&format!(
        "[DEBUG] Last 20 bytes of serialized ciphertext: {:?}",
        serialized_ciphertext
            .iter()
            .rev()
            .take(20)
            .collect::<Vec<_>>()
    ));

    // Deserialize the client key
    let client_key: ClientKey = match decode_from_slice(&serialized_client_key, standard()) {
        Ok((key, _)) => {
            log("[DEBUG] Client key deserialized successfully");
            key
        }
        Err(e) => {
            log(&format!("[DEBUG] Error deserializing client key: {:?}", e));
            return Err(JsValue::from_str(&format!(
                "Failed to deserialize client key: {:?}",
                e
            )));
        }
    };

    // Deserialize the ciphertext
    let ciphertext: Ciphertext = match decode_from_slice(&serialized_ciphertext, standard()) {
        Ok((ct, _)) => {
            log("[DEBUG] Ciphertext deserialized successfully");
            ct
        }
        Err(e) => {
            log(&format!("[DEBUG] Error deserializing ciphertext: {:?}", e));
            return Err(JsValue::from_str(&format!(
                "Failed to deserialize ciphertext: {:?}",
                e
            )));
        }
    };

    // Decrypt the ciphertext
    let raw_decrypted = client_key.decrypt(&ciphertext);
    let decrypted = raw_decrypted as u8;
    log(&format!(
        "[DEBUG] Decrypted value: {} (raw u64: {})",
        decrypted, raw_decrypted
    ));

    // Test encryption/decryption with the same client key
    let test_value = 1u8;
    let test_cipher = client_key.encrypt(test_value as u64);
    let test_decrypted = client_key.decrypt(&test_cipher) as u8;
    log(&format!(
        "[DEBUG] Test encryption with same key: {} -> {} (should be {})",
        test_value, test_decrypted, test_value
    ));

    Ok(decrypted)
}
