fn padding(bytes: &[u8], size: usize, fill: u8) -> Vec<u8> {
    let mut res = bytes.to_vec();
    let add = size - bytes.len();
    if add > 0 {
        for i in 0..add {
            res.push(fill);
        }
    }
    res
}

#[test]
fn challenge9() {
    let arr = b"YELLOW SUBMARINE";
    let d = padding(arr, 20, 4u8);
    assert_eq!(d, b"YELLOW SUBMARINE\x04\x04\x04\x04");
}
