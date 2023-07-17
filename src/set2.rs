use openssl::symm::{Cipher, Crypter, Mode};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use std::cmp;
use std::collections::HashMap;
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

fn parse_kv(input: &str) -> HashMap<&str, &str> {
    input
        .split('&')
        .map(|s| s.split('='))
        .map(|mut pair| (pair.next().unwrap(), pair.next().unwrap()))
        .collect::<HashMap<_, _>>()
}

fn encode_kv(input: &HashMap<&str, &str>) -> String {
    let mut keys = input.keys().collect::<Vec<&&str>>();
    keys.sort();

    keys.into_iter()
        .map(|k| format!("{}={}", k, input[k]))
        .collect::<Vec<String>>()
        .join("&")
        .to_string()
}

const PROFILE_KEY: &[u8; 16] = b"YELLOW SUBMARINE";

fn profile_for(mail: &str, role: &str) -> String {
    let profile: HashMap<&str, &str> =
        HashMap::from([("email", mail), ("uid", "10"), ("role", role)]);
    encode_kv(&profile)
}

fn encrypt_profile(profile: &str) -> Vec<u8> {
    ecb_encrypt(profile.as_bytes(), PROFILE_KEY)
}

fn decrypt_profile(profile: &[u8]) -> String {
    let dec = ecb_decrypt(profile, PROFILE_KEY);
    let mut pad_end = dec.len();
    for i in 0..dec.len() {
        if dec[dec.len() - i - 1] != 0 {
            pad_end = dec.len() - i;
            break;
        }
    }
    println!("{:?}", dec);
    str::from_utf8(&dec[0..pad_end]).unwrap().trim().to_string()
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
        let use_ecb = rng.gen_range(0..=1);
        let target = padding(
            &bytes[i * block_size..cmp::min((i + 1) * block_size, bytes.len())],
            block_size,
            0,
        );
        if use_ecb == 0 {
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

fn encryption_oracle14(input: &[u8]) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(0);
    let key = rng.gen::<[u8; 16]>();
    let block_size = 16usize;
    let mut bytes = vec![0; rng.gen_range(1..50)];
    rng.fill_bytes(&mut bytes);
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

fn encrypt_cookie(input: &str) -> Vec<u8> {
    let mut target = "comment1=cooking%20MCs;userdata=".to_string();
    target += &input.replace(";", "\\;").replace("=", "\\=");
    target += ";comment2=%20like%20a%20pound%20of%20bacon";
    cbc_encrypt(target.as_bytes(), PROFILE_KEY, b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F").unwrap()
}

fn decrypt_cookie(bytes: &[u8]) -> bool {
    let res = cbc_decrypt(bytes, PROFILE_KEY, b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F").unwrap();
    let str = unsafe {str::from_utf8_unchecked(&res)};
    println!("{}", str);
    str.contains(";admin=true;")
}

fn ecb_encrypt(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 16;
    let mut output = Vec::new();
    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &key, Some(&[])).unwrap();
    let mut buffer = [0; BLOCK_SIZE * 2];

    for i in 0..(bytes.len() + BLOCK_SIZE - 1) / BLOCK_SIZE {
        let target = padding(
            &bytes[i * BLOCK_SIZE..cmp::min((i + 1) * BLOCK_SIZE, bytes.len())],
            BLOCK_SIZE,
            0,
        );
        crypter.pad(false);
        let count = crypter.update(&target[..], &mut buffer).unwrap();
        output.extend_from_slice(&buffer[0..count]);
    }
    let count = crypter.finalize(&mut buffer).unwrap();
    output.extend_from_slice(&buffer[0..count]);
    output
}

fn ecb_decrypt(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 16;
    let mut output = Vec::new();
    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, &key, Some(&[])).unwrap();
    let mut buffer = [0; BLOCK_SIZE * 2];

    for i in 0..(bytes.len() + BLOCK_SIZE - 1) / BLOCK_SIZE {
        let target = &bytes[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        crypter.pad(false);
        let count = crypter.update(&target[..], &mut buffer).unwrap();
        output.extend_from_slice(&buffer[0..count]);
    }
    let count = crypter.finalize(&mut buffer).unwrap();
    output.extend_from_slice(&buffer[0..count]);
    output
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
        if ecb_found {
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

pub fn challenge14() {
    const BLOCK_SIZE: usize = 16;
    // find prefix length
    let len = BLOCK_SIZE * 6;
    let mut input = vec![0; len];
    let org = encryption_oracle14(&input);
    let mut boundary_block_index = 0;
    println!("{:?}", org);

    for i in 0..(org.len() + BLOCK_SIZE - 1) / BLOCK_SIZE - 1 {
        if &org[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]
            == &org[(i + 1) * BLOCK_SIZE..(i + 2) * BLOCK_SIZE]
        {
            boundary_block_index = i - 1;
            break;
        }
    }

    input = vec![0; BLOCK_SIZE];
    /*
     * | 123456   789012345678  901234
     * | prefix |    input    | target |
     * | 123456 | 000000000000| xxxxxx |
     * | 123456 | 000000000001| xxxxxx |
     * |
     */
    let mut prefix_offset = 0;
    for i in 0..BLOCK_SIZE {
        input[BLOCK_SIZE - i - 1] = 1;
        let new = encryption_oracle14(&input);
        if &new[boundary_block_index * BLOCK_SIZE..(boundary_block_index + 1) * BLOCK_SIZE]
            != &org[boundary_block_index * BLOCK_SIZE..(boundary_block_index + 1) * BLOCK_SIZE]
        {
            prefix_offset = i;
            break;
        }
        input[BLOCK_SIZE - i - 1] = 0;
    }
    let prefix_len = boundary_block_index * BLOCK_SIZE + prefix_offset;
    println!(
        "prefix_tail_block:{}, prefix_offset: {}",
        boundary_block_index, prefix_offset
    );

    let target_len = encryption_oracle14(&vec![0; 1]).len() - prefix_len - 1;
    let mut input = vec![
        0;
        ((target_len + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE + BLOCK_SIZE
            - prefix_offset
    ];
    let len = input.len();
    let mut result = Vec::new();
    println!("{}, {}", target_len, len);
    for i in 0..len {
        let res = encryption_oracle14(&input[0..len - i - 1]);
        if res.len() < len + prefix_len {
            break;
        }
        let org = &res[0..len + prefix_len];
        // println!("{:?}", org);
        input.remove(0);
        input.push(0);
        for c in 0..128 {
            input[len - 1] = c;
            let res = &encryption_oracle14(&input[0..len])[0..len + prefix_len];
            if org == res {
                println!("found: {}", c);
                result.push(c);
                break;
            }
        }
        println!("{:?}", input);
    }
    println!("{}", str::from_utf8(&result).unwrap());
}

fn validate_pkcs_padding(bytes: &[u8]) -> bool {
    const BLOCK_SIZE: usize = 16;
    if bytes.len() % BLOCK_SIZE != 0 {
        return false;
    }
    let mut count = 0u8;
    let last = bytes[bytes.len() - 1];
    for i in 0..BLOCK_SIZE {
        if bytes[bytes.len() - i - 1] == last {
            count += 1;
        } else {
            break;
        }
    }
    count == last
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

#[test]
fn kv_test() {
    let input = "baz=qux&foo=bar&zap=zazzle";
    let res = parse_kv(input);
    assert_eq!(
        res,
        HashMap::from([("foo", "bar"), ("baz", "qux"), ("zap", "zazzle")])
    );
    let kv = encode_kv(&HashMap::from([
        ("foo", "bar"),
        ("baz", "qux"),
        ("zap", "zazzle"),
    ]));
    assert_eq!(input, kv);
}

#[test]
fn challenge13() {
    let profile = profile_for("user1@example.com", "admin");
    let encrypted = encrypt_profile(&profile);
    println!("{:?}", encrypted);
    let decrypted = decrypt_profile(&encrypted);
    println!("{:?}", decrypted);
    assert_eq!(profile, decrypted);
}

#[test]
fn challenge15() {
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
        validate_pkcs_padding(b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"),
        true
    );
    assert_eq!(
        validate_pkcs_padding(b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"),
        false
    );
}

#[test]
fn challenge16() {
    /*
     * ; 0011 1011
     * : 0011 1010
     * = 0011 1101
     * 9 0011 1001
     */
    let mut encrypted = encrypt_cookie("1234567890123456:admin9true:");
    encrypted[32] ^= 1;
    encrypted[38] ^= 4;
    encrypted[43] ^= 1;
    let res = decrypt_cookie(&encrypted);
    assert_eq!(res, true);
}