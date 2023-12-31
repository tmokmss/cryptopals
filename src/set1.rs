use base64::{engine::general_purpose, Engine as _};
use openssl::symm::{decrypt, Cipher};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::str;
use std::{fmt::Write, num::ParseIntError};

use super::break_xor;

fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn challenge1() {
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();
    buffer.pop();
    let arr = decode_hex(buffer.as_str()).unwrap();

    // challenge 1: output base64 encoded string
    let encoded: String = general_purpose::STANDARD_NO_PAD.encode(arr);
    println!("{}", encoded);
}

pub fn challenge2() {
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();
    buffer.pop();
    let arr1 = decode_hex(buffer.as_str()).unwrap();

    buffer.clear();
    io::stdin().read_line(&mut buffer).unwrap();
    buffer.pop();
    println!("{}", buffer);

    let arr2 = decode_hex(buffer.as_str()).unwrap();

    // challenge 2: xor two hex strings
    let mut result = Vec::new();
    for i in 0..arr1.len() {
        result.push(arr1[i] ^ arr2[i]);
    }
    let result_str = encode_hex(&result);
    println!("{}", result_str);
}

fn score_english(s: &str) -> i32 {
    // count the number of letter "e" in the argument
    let mut score = 0;
    let mut space = 0;
    for c in s.to_lowercase().chars() {
        if c == 'e' || c == 'a' || c == 'i' || c == 'o' || c == 'u' {
            score += 1;
        }
        if c == ' ' {
            space += 1;
        }
    }
    if space > 2 {
        score
    } else {
        0
    }
}

pub fn challenge3() {
    // 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();
    buffer.pop();
    let arr1 = decode_hex(buffer.as_str()).unwrap();

    let mut max_score = 0;
    let mut ans: String = "dummy".to_string();
    // Iterate over all the alphabets
    for c in b'A'..=b'z' {
        let mut result = Vec::new(); // Create a new vector for each iteration
        for i in 0..arr1.len() {
            result.push(arr1[i] ^ c);
        }
        let s = str::from_utf8(&result).unwrap();
        // println!("{}", s);
        let score = score_english(s);
        if score > max_score {
            max_score = score;
            ans = s.to_string();
        }
    }
    println!("{}", ans);
}

pub fn challenge4() {
    let contents = fs::read_to_string("./input/1-4.txt").unwrap();
    let lines: Vec<String> = contents.split("\n").map(|s: &str| s.to_string()).collect();
    for line in lines {
        // println!("{}", line);

        let arr = decode_hex(line.as_str()).unwrap();
        let mut max_score = 0;
        let mut ans: String = "dummy".to_string();
        // Iterate over all the alphabets
        for c in b'!'..=b'~' {
            let mut result = Vec::new(); // Create a new vector for each iteration
            for i in 0..arr.len() {
                result.push(arr[i] ^ c);
            }
            let s = str::from_utf8(&result);
            if let Ok(s) = s {
                // println!("{}", s);
                let score = score_english(s);
                if score > max_score {
                    max_score = score;
                    ans = s.to_string();
                }
            }
        }
        if ans != "dummy" {
            println!("{}, {}", ans, line);
        }
    }
}

pub fn challenge5() {
    let contents = fs::read_to_string("./input/1-5.txt").unwrap();
    let key = [b'I', b'C', b'E'];
    let mut result = Vec::new(); // Create a new vector for each iteration
    for (i, c) in contents.as_bytes().iter().enumerate() {
        let k = i % key.len();
        result.push(c ^ key[k]);
    }
    println!("{}", encode_hex(&result));
}

pub fn challenge6() {
    let contents = fs::read_to_string("./input/1-6.txt")
        .unwrap()
        .replace("\n", "");
    break_xor::break_xor(contents.as_str());
}

pub fn challenge7() {
    let contents = fs::read_to_string("./input/1-7.txt")
        .unwrap()
        .replace("\n", "");
    let input = general_purpose::STANDARD.decode(contents).unwrap();
    let key = b"YELLOW SUBMARINE";
    let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
    let cipher = Cipher::aes_128_ecb();
    let decrypted = decrypt(cipher, key, Some(iv), input.borrow()).unwrap();
    println!("{}", str::from_utf8(&decrypted).unwrap());
}

pub fn challenge8() {
    let contents: Vec<String> = fs::read_to_string("./input/1-8.txt")
        .unwrap()
        .split("\n")
        .map(|s| s.to_string())
        .collect();
    for s in contents {
        let mut counts = HashMap::new();
        for i in 0..s.len() / 32 {
            let c = counts.entry(&s[i * 32..((i + 1) * 32)]).or_insert(0);
            *c += 1;
        }
        if counts.values().any(|c| c > &1) {
            println!("{}", s);
            println!("{:?}", counts);
        }
    }
}
