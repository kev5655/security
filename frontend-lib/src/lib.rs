mod utils;

use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};
use wasm_bindgen::prelude::*;

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
pub fn encrypt(data: u8) -> Vec<u8> {
    let config = ConfigBuilder::default().build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);

    let clear_a = data;

    let a = FheUint8::encrypt(clear_a, &client_key);

    return bincode::serialize(&a).expect("serialize ciphertext");
}
