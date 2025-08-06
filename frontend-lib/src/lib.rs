mod utils;

use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};
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

#[wasm_bindgen]
pub fn encrypt(data: u8, serialized_key: Vec<u8>) -> Vec<u8> {
    let clientKey = Shortint.deserialize_client_key(serializedKey);

    let a = FheUint8::encrypt(data, &clientKey);

    return bincode::serialize(&a).expect("serialize ciphertext");
}
