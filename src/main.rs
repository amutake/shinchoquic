extern crate aes_ctr;
#[macro_use]
extern crate hex_literal;
extern crate ring;
extern crate rustls;
extern crate rand;
extern crate webpki;

mod ngtcp2;
mod quic;

fn main() {
    //ngtcp2::main();
    quic::main();
}
