extern crate aes_ctr;
#[macro_use]
extern crate hex_literal;
extern crate byteorder;
extern crate crypto;
extern crate rand;
extern crate ring;
extern crate rustls;
extern crate webpki;
extern crate webpki_roots;

mod ngtcp2;
mod quic;
mod util;

fn main() {
    quic::main();
    // ngtcp2::main();
}
