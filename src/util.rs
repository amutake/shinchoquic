use std::io::Write;

pub fn hex_to_string(hex: &[u8]) -> String {
    let mut w = Vec::new();
    write!(&mut w, "0x").unwrap();
    for b in hex.iter() {
        write!(&mut w, "{:02x}", b).unwrap();
    }
    String::from_utf8(w).unwrap()
}

pub fn print_hex(key: &'static str, hex: &[u8]) {
    println!("{}: {}", key, hex_to_string(hex));
}

pub fn xor(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    assert_eq!(lhs.len(), rhs.len());
    lhs.iter().zip(rhs.iter()).map(|(l, r)| l ^ r).collect()
}

pub fn left_pad(a: &[u8], len: usize) -> Vec<u8> {
    let alen = a.len();
    assert!(len >= alen);
    let mut v = vec![0; len - alen];
    v.append(&mut a.to_vec());
    v
}
