use ::util::util::decode_hex;
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use std::fs;
use std::str;
use std::time::UNIX_EPOCH;

use crate::break_xor;
use crate::mt19937;
use crate::util::{self, validate_pkcs_padding};
use rand::distributions::{Alphanumeric, DistString};
use std::thread::sleep;
use std::time::{Duration, SystemTime};

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
    let answers: Vec<Vec<u8>> = crypts
        .iter()
        .map(|c| {
            let mut ans = vec![0u8; c.len()];
            for i in 0..c.len() {
                ans[i] = c[i] ^ result[i];
            }
            ans
        })
        .collect();
    println!("{:?}", answers);
    for ans in answers {
        println!("{}", str::from_utf8(&ans).unwrap());
    }
}

pub fn challenge20() {
    let inputs = util::load_base64_each_line("input/3-20.txt");
    let key = rand::thread_rng().gen::<[u8; 16]>();
    let crypts: Vec<Vec<u8>> = inputs.iter().map(|i| ctr_encrypt(i, &key, 0)).collect();

    let max_length = crypts.iter().map(|c: &Vec<u8>| c.len()).max().unwrap();
    let min_length = crypts.iter().map(|c| c.len()).min().unwrap();
    let mut key = vec![0u8; 0];
    for i in 0..=min_length {
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
        key.push(ans);
    }
    let answers: Vec<Vec<u8>> = crypts
        .iter()
        .map(|c| {
            let len = min_length;
            let mut ans = vec![0u8; len];
            for i in 0..len {
                ans[i] = c[i] ^ key[i];
            }
            ans
        })
        .collect();
    println!("{:?}", key);
    for ans in answers {
        println!("{}", str::from_utf8(&ans).unwrap());
    }
}

fn challenge22_helper() -> u32 {
    let mut rng = rand::thread_rng();
    let r = rng.gen_range(0..10);
    sleep(Duration::new(r, 0));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let mut rand = mt19937::MT19937::new(now);
    let r = rng.gen_range(0..10);
    sleep(Duration::new(r, 0));
    rand.next()
}

pub fn challenge22() {
    let start: u32 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let result = challenge22_helper();
    println!("first random number: {}", result);
    let end: u32 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    for i in start..=end {
        let mut rand = mt19937::MT19937::new(i);
        if result == rand.next() {
            println!("detecetd! {}", i);
            break;
        }
    }
}

pub fn challenge23() {
    let mut mt = mt19937::MT19937::new(1234);
    let mut state = [0u32; 624];
    for i in (0..state.len()) {
        let r = mt.next();
        state[i] = mt19937::untemper(r);
    }
    let mut mt_clone = mt19937::MT19937::from_state(state);
    println!("original: {}, clone:{}", mt.next(), mt_clone.next());
    println!("original: {}, clone:{}", mt.next(), mt_clone.next());
    println!("original: {}, clone:{}", mt.next(), mt_clone.next());
    println!("original: {}, clone:{}", mt.next(), mt_clone.next());
}

fn prng_encrypt(input: &[u8], rng: &mut mt19937::MT19937) -> Vec<u8> {
    const block_size: usize = 4usize;
    let mut result = vec![0u8; input.len()];
    for i in 0..((input.len() + block_size - 1) / block_size) {
        let r = rng.next().to_le_bytes();
        for j in 0..block_size {
            let idx = j + i * block_size;
            if idx >= input.len() {
                break;
            }
            result[idx] = input[idx] ^ r[j];
        }
    }

    result
}

fn generate_password_reset_token() -> String {
    let timestamp: u32 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let mut rand = mt19937::MT19937::new(timestamp);
    let vec = (0..5)
        .flat_map(|_| rand.next().to_le_bytes())
        .collect::<Vec<u8>>();
    util::encode_hex(&vec)
}

fn check_password_reset_token(token: &str) -> bool {
    let timestamp: u32 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let mut rand = mt19937::MT19937::new(timestamp);
    let vec = util::decode_hex(token);
    match vec {
        Ok(res) => {
            if res.len() % 4 != 0 {
                return false;
            }
            for i in 0..res.len() / 4 {
                let r = rand.next().to_le_bytes();
                for j in 0..4 {
                    if res[i * 4 + j] != r[j] {
                        return false;
                    }
                }
            }
            true
        }
        Err(_) => false,
    }
}

pub fn challenge24() {
    let mut rng = rand::thread_rng();
    let key: u16 = rng.gen();
    let prefix = Alphanumeric.sample_string(&mut rng, rand::thread_rng().gen_range(10..20));
    let plaintext = "AAAAAAAAAAAAAAAAAAAAA";
    let input = prefix + plaintext;
    println!("{}, seed: {} ", input, key);
    let mut mt = mt19937::MT19937::new(key as u32);

    // break seed
    let mut seed = 0;
    let res = prng_encrypt(input.as_bytes(), &mut mt);
    for i in 0..65536 {
        let mut mt = mt19937::MT19937::new(i);
        let prefix_len = res.len() - plaintext.len();

        const block_size: usize = 4usize;
        let mut found = true;
        for i in 0..((res.len() + block_size - 1) / block_size) {
            if !found {
                break;
            }
            let r = mt.next().to_le_bytes();
            for j in 0..block_size {
                let idx = j + i * block_size;
                if idx >= res.len() {
                    break;
                }
                if idx < prefix_len {
                    continue;
                }
                if res[idx] != (plaintext.as_bytes()[i] ^ r[j] as u8) {
                    found = false;
                    break;
                }
            }
        }

        if found {
            println!("Detected seed: {}", i);
            seed = i;
        }
    }

    let token = generate_password_reset_token();
    println!("password reset token: {}", token);
    // sleep(Duration::new(1, 0));
    println!("validate result: {}", check_password_reset_token(&token));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prng_encrypt() {
        let input = "asdfasdfbdgbkldjglbkdg";
        let mut mt = mt19937::MT19937::new(1234);
        let output = prng_encrypt(input.as_bytes(), &mut mt);
        let mut mt = mt19937::MT19937::new(1234);
        let output2 = prng_encrypt(&output, &mut mt);
        assert_eq!(input.as_bytes(), output2);
    }
}
