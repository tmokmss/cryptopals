use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use std::fs;
use std::str;

use crate::break_xor;
use crate::util::{self, validate_pkcs_padding};

const BLOCK_SIZE: usize = 16;

struct Challenge17 {
    key: [u8; 16],
    target: Vec<u8>,
}

impl Challenge17 {
    fn encrypt(&self) -> (Vec<u8>, Vec<u8>) {
        let iv = rand::thread_rng().gen::<[u8; BLOCK_SIZE]>().to_vec();
        let encrypted = util::cbc_encrypt(&self.target, &self.key, &iv).unwrap();
        (encrypted, iv)
    }

    fn decrypt_and_validate(&self, input: &[u8], iv: &[u8]) -> bool {
        let output = util::cbc_decrypt(input, &self.key, iv).unwrap();
        let res = util::validate_pkcs_padding(&output);
        // println!("{}, {:?}", res, output);
        res
    }
}

fn build_challenge17(choice: usize) -> Challenge17 {
    let mut rng = rand::thread_rng();
    let text = fs::read_to_string("input/3-17.txt").unwrap();
    let contents = text.split('\n');
    let count = contents.clone().count();
    let chosen = contents
        .skip(if choice < 10 {
            choice
        } else {
            rng.gen_range(0..count)
        })
        .next()
        .unwrap();

    Challenge17 {
        key: rand::thread_rng().gen::<[u8; 16]>(),
        target: general_purpose::STANDARD.decode(chosen).unwrap(),
    }
}

fn decrypt_block(block: &[u8], iv: &[u8], challenge: &Challenge17) -> Vec<u8> {
    if block.len() != BLOCK_SIZE || iv.len() != BLOCK_SIZE {
        panic!("input array length is not 16!");
    }

    let mut ivv: Vec<u8> = iv.to_vec();
    let mut dec = vec![0u8; BLOCK_SIZE];

    for i in 1..=BLOCK_SIZE {
        let iu8 = u8::try_from(i).unwrap();
        for j in 1..=BLOCK_SIZE {
            ivv[BLOCK_SIZE - j] = dec[BLOCK_SIZE - j] ^ (iu8);
        }
        for x in 0..=255u8 {
            ivv[BLOCK_SIZE - i] = x;
            if challenge.decrypt_and_validate(block, &ivv) {
                if i == 1 {
                    ivv[BLOCK_SIZE - 2] ^= 1;
                    if !challenge.decrypt_and_validate(block, &ivv) {
                        // false positive
                        // println!("false positive!");
                        ivv[BLOCK_SIZE - 2] ^= 1;
                        continue;
                    }
                }
                // padding is valid, so dec[-i] ^ x = i
                // dec[-i] = i ^ x
                // zeroing iv = i ^ x
                dec[BLOCK_SIZE - i] = (iu8) ^ x;
                break;
            }
            if x == 255 {
                print!("not found! {}, {}, {:?}\n", i, x, dec);
                return dec;
            }
        }
    }

    for i in 0..BLOCK_SIZE {
        dec[i] ^= iv[i];
    }

    dec
}

pub fn challenge17() {
    for q in 0..10 {
        let challenge = build_challenge17(q);
        let (encrypted, iv) = challenge.encrypt();
        let mut prev = iv;
        let mut result = vec![0u8, 0];
        for i in 0..(encrypted.len() / BLOCK_SIZE) {
            let block = &encrypted[(i * BLOCK_SIZE)..(i + 1) * BLOCK_SIZE];
            let mut decrypted = decrypt_block(block, &prev, &challenge);
            prev = block.to_vec();
            result.append(&mut decrypted);
            // println!("{}", str::from_utf8(&result).unwrap());
        }
        match str::from_utf8(&result) {
            Ok(res) => println!("{}", res),
            Err(error) => println!("{}", error),
        };
    }
}

fn ctr_encrypt(input: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    let block_size = 16usize;
    let mut result = vec![0u8; input.len()];
    for i in 0..((input.len() + block_size - 1) / block_size) {
        let target = [nonce.to_le_bytes(), u64::try_from(i).unwrap().to_le_bytes()].concat();
        // println!("{:?}", target);
        let stream = util::ecb_encrypt(&target, &key);
        for j in 0..block_size {
            let idx = j + i * block_size;
            if idx >= input.len() {
                break;
            }
            result[idx] = input[idx] ^ stream[j];
        }
    }

    result
}

pub fn challenge18() {
    let input = util::load_base64_ignoring_newlines("input/3-18.txt");
    let key = b"YELLOW SUBMARINE";
    let nonce = 0u64;
    let result = ctr_encrypt(&input, key, nonce);
    println!("{}", str::from_utf8(&result).unwrap());
}

pub fn challenge19() {
    let inputs = util::load_base64_each_line("input/3-19.txt");
    let key = rand::thread_rng().gen::<[u8; 16]>();
    let crypts: Vec<Vec<u8>> = inputs.iter().map(|i| ctr_encrypt(i, &key, 0)).collect();
    let mut result = vec![0u8; 0];
    for i in 0..=40 {
        let mut max = 0f64;
        let mut ans = 0;
        for x in 0..=255u8 {
            let s: Vec<u8> = crypts
                .iter()
                .map(|c| if i < c.len() { c[i] ^ x } else { 0 })
                .collect();
            let score = break_xor::score_english(&s);
            if score > max {
                ans = x;
                max = score;
            }
        }
        result.push(ans);
    }
    let answers: Vec<Vec<u8>> = crypts.iter().map(|c| {
        let mut ans = vec![0u8; c.len()];
        for i in 0..c.len() {
            ans[i] = c[i] ^ result[i];
        }
        ans
    }).collect();
    println!("{:?}", answers);
    for ans in answers {
        println!("{}", str::from_utf8(&ans).unwrap());
    }
}
