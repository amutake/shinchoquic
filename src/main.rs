extern crate aes_ctr;
#[macro_use]
extern crate hex_literal;
extern crate byteorder;
extern crate crypto as rust_crypto;
extern crate rand;
extern crate ring;
extern crate rustls;
extern crate webpki;
extern crate webpki_roots;

use rustls::quic::{ClientQuicExt, Keys, QuicExt, Side};
use rustls::suites::TLS13_AES_128_GCM_SHA256;
use rustls::{ClientConfig, ClientSession, ProtocolVersion, Session, SupportedCipherSuite};
use std::net;
use std::sync::Arc;
use webpki::DNSNameRef;
use webpki_roots::TLS_SERVER_ROOTS;

mod crypto;
mod error;
mod ngtcp2;
mod packet;
mod quic;
mod util;

use packet::*;

fn main() {
    // quic::main();
    // ngtcp2::main();

    let mut config = ClientConfig::new();
    config.ciphersuites = vec![&TLS13_AES_128_GCM_SHA256];
    config.versions = vec![ProtocolVersion::TLSv1_3];
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let config = Arc::new(config);
    // ngtcp2 のトランスポートパラメータを引っこ抜いてきた :innocent:
    let params = hex!("ff00000e003200030002001e0000000400040000000a000400040000000b0004000400000001000400100000000200020001000800020001").to_vec();
    let hostname = DNSNameRef::try_from_ascii_str("localhost").unwrap();
    let mut session = ClientSession::new_quic(&config, hostname, params);

    let dst_conn_id = ConnectionId::new(hex!("f2aca972962edd0f195aa1bb9a16734be91b").to_vec());
    let src_conn_id = ConnectionId::new(hex!("d545b3713ec650dc4844f59652f737fa3a").to_vec());

    let mut pn_spaces = packet::PacketNumberSpaces::new();
    let keys = crypto::PhaseKeys::new(&dst_conn_id);

    let packet = packet::Packet::Initial {
        version: 0xff00000e,
        dst_conn_id,
        src_conn_id,
        token: vec![],
        packet_number: pn_spaces.next_initial(),
        payload: packet::Payload(vec![packet::Frame::Crypto { offset:0, payload: hex!("010001270303ec616ce0718ff6cc0beef7fd70d3e2cfa791b9d8a78ba9d4acae89e58d99e11c00000813021303130100ff010000f6ffa50038ff00000e003200030002001e0000000400040000000a000400040000000b00040004000000010004001000000002000200010008000200010000000e000c0000096c6f63616c686f7374000b000403000102000a000a00080017001d00180019002300000010000800060568712d31340016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d0002010100330047004500170041048f5a12125ccca5667935e64dd2b9923b0df1c97e3d3212dc5b4aa7b036ef0faec05aeac66fe0866d9de85fae29960d954baf81ec68e3619a0712393e14945422").to_vec() }]),
    };
    let mut buf = [0; 1500];

    let amt = packet.encode(&keys, &mut buf).unwrap();

    util::print_hex("packet", &buf[..amt]);

    use ngtcp2;
    ngtcp2::decode_print(ngtcp2::Side::Client, &buf[..amt]);
}
