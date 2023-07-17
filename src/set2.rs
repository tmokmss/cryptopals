use openssl::symm::{Cipher, Crypter, Mode};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::cmp;
use std::str;

use super::util;

fn padding(bytes: &[u8], size: usize, fill: u8) -> Vec<u8> {
    let mut res = bytes.to_vec();
    let add = size - bytes.len();
    if add > 0 {
        for _ in 0..add {
            res.push(fill);
        }
    }
    res
}

fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![rng.gen_range(1u8..128u8); rng.gen_range(1..5)];
    bytes.extend_from_slice(input);
    bytes.append(&mut vec![rng.gen_range(1u8..128u8); rng.gen_range(1..5)]);
    let block_size = 16usize;
    let mut res = Vec::new();
    let key = rand::thread_rng().gen::<[u8; 16]>();

    for i in 0..(bytes.len() + block_size - 1) / block_size {
        let useEcb = rng.gen_range(0..=1);
        let target = padding(
            &bytes[i * block_size..cmp::min((i + 1) * block_size, bytes.len())],
            block_size,
            0,
        );
        if useEcb == 0 {
            let mut encrypter =
                Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &key, Some(&[])).unwrap();
            encrypter.pad(false);
            let mut output = vec![0; bytes.len() + block_size];
            let mut count = encrypter.update(&target[..], &mut output).unwrap();
            count += encrypter.finalize(&mut output[count..]).unwrap();
            output.truncate(count);
            res.append(&mut output);
        } else {
            // cbc
            let iv = rand::thread_rng().gen::<[u8; 16]>();
            let mut output = cbc_encrypt(&target[..], &key, &iv).unwrap();
            res.append(&mut output);
        }
    }
    res
}

fn encryption_oracle12(input: &[u8]) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(0);
    let key = rng.gen::<[u8; 16]>();
    let block_size = 16usize;
    let mut bytes = vec![];
    bytes.extend_from_slice(input);
    let secret = util::load_base64_ignoring_newlines("input/2-12.txt");
    bytes.extend(secret);
    let mut res = Vec::new();

    for i in 0..(bytes.len() + block_size - 1) / block_size {
        let target = padding(
            &bytes[i * block_size..cmp::min((i + 1) * block_size, bytes.len())],
            block_size,
            0,
        );
        let mut encrypter =
            Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &key, Some(&[])).unwrap();
        encrypter.pad(false);
        let mut output = vec![0; bytes.len() + block_size];
        let mut count = encrypter.update(&target[..], &mut output).unwrap();
        count += encrypter.finalize(&mut output[count..]).unwrap();
        output.truncate(count);
        res.append(&mut output);
    }
    res
}

fn cbc_encrypt(bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, &'static str> {
    let block_size = 16usize;
    if iv.len() != block_size {
        return Err("invalid iv length");
    }
    let mut res = Vec::new();
    let mut prev = iv;

    for i in 0..(bytes.len() + block_size - 1) / block_size {
        let mut encrypter =
            Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, Some(iv)).unwrap();
        encrypter.pad(false);

        let mut output = vec![0; bytes.len() + block_size];
        let target = padding(
            &bytes[i * block_size..cmp::min((i + 1) * block_size, bytes.len())],
            block_size,
            0,
        );
        let input = (0..block_size)
            .map(|i| prev[i] ^ target[i])
            .collect::<Vec<u8>>();
        let mut count = encrypter.update(&input[..], &mut output).unwrap();
        count += encrypter.finalize(&mut output[count..]).unwrap();
        output.truncate(count);
        res.append(&mut output);
        prev = &res[i * block_size..(i + 1) * block_size];
    }
    Ok(res)
}

fn cbc_decrypt(bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, &'static str> {
    let block_size = 16usize;
    if iv.len() != block_size {
        return Err("invalid iv length");
    }
    let mut res = Vec::new();
    let mut prev: &[u8] = iv;
    for i in 0..(bytes.len() + block_size - 1) / block_size {
        let mut decrypter =
            Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, Some(iv)).unwrap();
        decrypter.pad(false);

        let mut decrypted = vec![0; bytes.len() + block_size];
        let target = &bytes[i * block_size..(i + 1) * block_size];
        let mut count = decrypter.update(target, &mut decrypted).unwrap();
        count += decrypter.finalize(&mut decrypted[count..]).unwrap();
        decrypted.truncate(count);
        let mut input = (0..block_size)
            .map(|i| prev[i] ^ decrypted[i])
            .collect::<Vec<u8>>();
        res.append(&mut input);
        prev = &bytes[i * block_size..(i + 1) * block_size];
    }
    Ok(res)
}

pub fn challenge10() {
    let input = util::load_base64_ignoring_newlines("input/2-10.txt");
    let key = b"YELLOW SUBMARINE";
    let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let decrypted = cbc_decrypt(&input[..], key, iv).unwrap();

    println!("{}", str::from_utf8(&decrypted).unwrap());
}

pub fn challenge11() {
    let input = [0u8; 200];
    let crypt = encryption_oracle(&input);
    println!("{:?}", crypt);
    let mut ecb_found = false;
    let mut ecb: &[u8] = &[];
    let block_size = 16;
    let mut result = vec![false];
    for i in 1..crypt.len() / block_size {
        let me = &crypt[i * block_size..(i + 1) * block_size];
        if (ecb_found) {
            result.push(me == ecb);
        } else {
            for j in i..crypt.len() / block_size {
                if me == &crypt[j * block_size..(j + 1) * block_size] {
                    ecb_found = true;
                    ecb = me;
                    break;
                }
            }
            result.push(ecb_found);
        }
    }
    println!("{:?}", result);
}

pub fn challenge12() {
    for i in 0..20 {
        let res = encryption_oracle12(&vec![0; i]);
        // println!("{}", res.len());
        // block_size = 16
    }
    let block_size = 16;
    let target_len = encryption_oracle12(&vec![0; 1]).len();
    let mut input = vec![0; (target_len + block_size - 1) / block_size * block_size];
    let len = input.len();
    let mut result = Vec::new();
    println!("{}, {}", target_len, len);
    for i in 0..len {
        let org = &encryption_oracle12(&input[0..len - i - 1])[0..len];
        // println!("{:?}", org);
        input.remove(0);
        input.push(0);
        for c in 0..128 {
            input[len - 1] = c;
            let res = &encryption_oracle12(&input[0..len])[0..len];
            if org == res {
                // println!("found: {}", c);
                result.push(c);
                break;
            }
        }
        println!("{:?}", input);
    }
    println!("{}", str::from_utf8(&result).unwrap());
}

#[test]
fn challenge9() {
    let arr = b"YELLOW SUBMARINE";
    let d = padding(arr, 20, 4u8);
    assert_eq!(d, b"YELLOW SUBMARINE\x04\x04\x04\x04");
}

#[test]
fn challenge10_test() {
    let key = b"YELLOW SUBMARINE";
    let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let input = b"qwertyuiopasdfghjklzxcvbnm,.1234567890";
    let encrypted = cbc_encrypt(input, key, iv).unwrap();
    let decrypted = cbc_decrypt(&encrypted[..], key, iv).unwrap();
    assert_eq!(input, &decrypted[0..input.len()]);
}
