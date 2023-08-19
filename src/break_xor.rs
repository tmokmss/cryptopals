use base64::{engine::general_purpose, Engine as _};
use std::fmt::Write;
use std::str;

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

// humming distance
fn distance(lhs: &[u8], rhs: &[u8]) -> f32 {
    let mut distance = 0f32;
    for i in 0..lhs.len() {
        distance += (lhs[i] ^ rhs[i]).count_ones() as f32;
    }
    distance
}

fn search_key_length(input: &[u8]) -> u32 {
    let mut res: Vec<(usize, f32)> = Vec::new();
    for i in 2..41 {
        let mut d = 0f32;
        for j in 0..input.len() / (2 * i) {
            d += distance(&input[i * j..i * (j + 1)], &input[i * (j + 1)..i * (j + 2)]);
        }
        res.push((i, d / (input.len() / (2 * i) - 1) as f32 / i as f32));
    }
    res.sort_by(|a, b| a.1.total_cmp(&b.1));
    println!("{:#?}", res);
    res[0].0 as u32
}

fn split(input: &[u8], key_length: u32) -> Vec<Vec<u8>> {
    let mut res = Vec::new();
    for i in 0..key_length {
        let mut temp = Vec::new();
        for j in 0..input.len() as u32 / key_length {
            temp.push(input[(i + j * key_length) as usize]);
        }
        res.push(temp);
    }
    res
}

pub fn score_english(s: &[u8]) -> f64 {
    let prob = [
        8.4966,  // "A"
        2.0720,  // "B"
        2.5388,  // "C"
        4.0250,  // "D"
        11.1607, // "E"
        2.2282,  // "F"
        2.0153,  // "G"
        6.0943,  // "H"
        7.5448,  // "I"
        0.153,   // "J"
        1.292,   // "K"
        4.0250,  // "L"
        2.4060,  // "M"
        7.3846,  // "N"
        7.5462,  // "O"
        2.3073,  // "P"
        0.1965,  // "Q"
        5.9879,  // "R"
        6.3270,  // "S"
        9.3560,  // "T"
        2.7588,  // "U"
        0.978,   // "V"
        2.560,   // "W"
        0.150,   // "X"
        1.994,   // "Y"
        0.077,   // "Z"
    ];
    let mut raw: [f64; 26] = [0.0; 26];

    for cs in s {
        let mut c = cs.clone();
        if c >= b'A' && c <= b'Z' {
            c = c + 32;
        }
        if c < b'a' || c > b'z' {
            continue;
        }
        raw[(c - b'a') as usize] += 1.0;
    }
    for i in 0..26 {
        raw[i] = raw[i] / s.len() as f64 * 100.0;
    }
    prob.iter().zip(raw.iter()).map(|(x, y)| x * y).sum()
}

fn break_single_xor(input: &[u8]) -> u8 {
    let mut max_score: f64 = 0.0;
    let mut ans: u8 = 0;
    let mut anss: String = "".to_string();
    println!("{}", input.len());
    // Iterate over all the alphabets
    for c in 0..127 {
        let mut result = Vec::new(); // Create a new vector for each iteration
        for i in 0..input.len() {
            result.push(input[i] ^ c);
        }
        let s = str::from_utf8(&result).unwrap();
        let score = score_english(&result);
        if score > max_score {
            anss = s.to_string();
            max_score = score;
            ans = c;
        }
    }
    println!("{}", anss);
    ans
}

pub fn break_xor(base64_string: &str) {
    let input = general_purpose::STANDARD.decode(base64_string).unwrap();
    let key_length = search_key_length(&input);
    let splitted = split(&input, key_length);
    let mut key = Vec::new(); // Create a new vector for each iteration
    for sp in splitted {
        let keyc = break_single_xor(&sp);
        key.push(keyc);
    }
    println!("{:?}", key);
    let mut result = Vec::new(); // Create a new vector for each iteration
    for (i, c) in input.iter().enumerate() {
        let k = i % key.len();
        result.push(c ^ key[k]);
    }
    println!("{}", str::from_utf8(&result).unwrap());
    // let mut result = Vec::new(); // Create a new vector for each iteration
}

#[test]
fn it_works() {
    let d = distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes());
    assert_eq!(d, 37f32);
}
