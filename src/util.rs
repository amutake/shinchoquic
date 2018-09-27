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
