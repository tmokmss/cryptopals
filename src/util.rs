use base64::{engine::general_purpose, Engine as _};
use openssl::symm::{Cipher, Crypter, Mode};
use std::cmp;
use std::fs;
use std::str;

pub fn load_base64_ignoring_newlines(path: &str) -> Vec<u8> {
    let contents = fs::read_to_string(path).unwrap().replace("\n", "");
    general_purpose::STANDARD.decode(contents).unwrap()
}

pub fn load_base64_each_line(path: &str) -> Vec<Vec<u8>> {
    fs::read_to_string(path).unwrap().split("\n").map(|line| general_purpose::STANDARD.decode(line).unwrap()).collect()
}

pub fn pkcs_padding(bytes: &mut Vec<u8>, size: u8) {
    let remain = u8::try_from(bytes.len() % (size as usize)).unwrap();
    let add = size - remain;
    if add > 0 {
        for _ in 0..add {
            bytes.push(add);
        }
    }
}

/// # Examples
/// ```
/// assert_eq!(util::util::validate_pkcs_padding(b"YELLOW SUBMARINE"), false);
/// assert_eq!(util::util::validate_pkcs_padding(b"ICE ICE BABY\x04\x04\x04\x04"), true);
/// ```
pub fn validate_pkcs_padding(bytes: &[u8]) -> bool {
    const BLOCK_SIZE: usize = 16;
    if bytes.len() % BLOCK_SIZE != 0 {
        return false;
    }
    let last = bytes[bytes.len() - 1];
    if last as usize > BLOCK_SIZE || last == 0 {
        return false;
    }
    for i in 1..=last as usize {
        if bytes[bytes.len() - i] != last {
            return false;
        }
    }
    true
}

pub fn ecb_encrypt(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 16;
    let mut output = Vec::new();
    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &key, Some(&[])).unwrap();
    let mut buffer = [0; BLOCK_SIZE * 2];
    let mut input = bytes.to_vec();

    pkcs_padding(&mut input, u8::try_from(BLOCK_SIZE).unwrap());
    for i in 0..(input.len() + BLOCK_SIZE - 1) / BLOCK_SIZE {
        let target = &input[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        crypter.pad(false);
        let count = crypter.update(&target[..], &mut buffer).unwrap();
        output.extend_from_slice(&buffer[0..count]);
    }
    let count = crypter.finalize(&mut buffer).unwrap();
    output.extend_from_slice(&buffer[0..count]);
    output
}

pub fn cbc_encrypt(bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, &'static str> {
    let block_size = 16usize;
    if iv.len() != block_size {
        return Err("invalid iv length");
    }
    let mut res = Vec::new();
    let mut prev = iv;
    let mut input = bytes.to_vec();

    pkcs_padding(&mut input, u8::try_from(block_size).unwrap());
    for i in 0..(input.len() + block_size - 1) / block_size {
        let mut encrypter =
            Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, Some(iv)).unwrap();
        encrypter.pad(false);

        let mut output = vec![0; input.len() + block_size];
        let target = &input[i * block_size..(i + 1) * block_size];
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

pub fn cbc_decrypt(bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, &'static str> {
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

#[test]
fn test_validate_pkcs_padding() {
    assert_eq!(validate_pkcs_padding(b"YELLOW SUBMARINE"), false);
    assert_eq!(validate_pkcs_padding(b"ICE ICE BABY\x04\x04\x04\x04"), true);
    assert_eq!(
        validate_pkcs_padding(b"ICE ICE BABY\x05\x05\x05\x05"),
        false
    );
    assert_eq!(
        validate_pkcs_padding(b"ICE ICE BAB\x05\x05\x05\x05\x05"),
        true
    );
    assert_eq!(
        validate_pkcs_padding(b"ICE ICE BA\x05\x05\x05\x05\x05\x05"),
        true
    );
    assert_eq!(
        validate_pkcs_padding(b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"),
        true
    );
    assert_eq!(
        validate_pkcs_padding(b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"),
        false
    );
}
