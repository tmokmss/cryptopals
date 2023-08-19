use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use std::fs;
use std::str;

use crate::util::{self, validate_pkcs_padding};

const BLOCK_SIZE: usize = 16;

struct Challenge17 {
    key: [u8; 16],
    target: Vec<u8>,
}

impl Challenge17 {
    fn encrypt(&self) -> (Vec<u8>, Vec<u8>) {
        let iv =  rand::thread_rng().gen::<[u8; BLOCK_SIZE]>().to_vec();
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
