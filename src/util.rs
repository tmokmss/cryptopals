use base64::{engine::general_purpose, Engine as _};
use std::fs;
use std::str;

pub fn load_base64_ignoring_newlines(path: &str) -> Vec<u8> {
    let contents = fs::read_to_string(path).unwrap().replace("\n", "");
    general_purpose::STANDARD.decode(contents).unwrap()
}
