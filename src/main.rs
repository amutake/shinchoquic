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

    let socket = net::UdpSocket::bind("0.0.0.0:0").unwrap();

    // send client initial
    let dst_conn_id = ConnectionId::random();
    let src_conn_id = ConnectionId::random();

    let mut pn_spaces = packet::PacketNumberSpaces::new();
    let mut keys = crypto::PhaseKeys::new(&dst_conn_id);

    let mut crypto = vec![];
    session.write_hs(&mut crypto);
    let packet = packet::Packet::Initial {
        version: 0xff00000e,
        dst_conn_id,
        src_conn_id,
        token: vec![],
        packet_number: pn_spaces.next_initial(),
        payload: packet::Payload {
            frames: vec![packet::Frame::Crypto {
                offset: 0,
                payload: crypto,
            }],
        },
    };
    let mut buf = [0; 1500];
    let amt = packet
        .encode(&keys, &mut buf)
        .expect("failed to encode client initial packet");
    let client_initial = &buf[..amt];
    util::print_hex("client initial", &client_initial);
    socket
        .send_to(&client_initial, "127.0.0.1:4433")
        .expect("failed to send client initial packet");

    // recv server initial + handshake
    let mut buf = [0; 1500];
    let (amt, _) = socket
        .recv_from(&mut buf)
        .expect("failed to recv server initial + handshake packet");
    let buf = &buf[..amt];
    util::print_hex("server initial", buf);
    let (server_initial, amt) =
        packet::Packet::decode(&buf, &keys).expect("failed to decode server initial packet");
    println!("server initial: {:?}", server_initial);
    let buf = &buf[amt..];

    let crypto = match server_initial {
        packet::Packet::Initial { ref payload, .. } => match payload.frames.get(1) {
            // TODO: offset もちゃんと扱う
            Some(packet::Frame::Crypto { payload, .. }) => payload,
            _ => panic!("server initial frame[1] must be a crypto frame"),
        },
        _ => panic!("first message from server must be an initial packet"),
    };
    session.read_hs(&crypto).unwrap();
    match session.get_handshake_keys() {
        Some(handshake_keys) => {
            keys.set_handshake(handshake_keys);
        }
        _ => panic!("failed to get handshake keys"),
    }

    let (server_handshake, amt) =
        packet::Packet::decode(&buf, &keys).expect("failed to decode server handshake packet");
    println!("server handshake: {:?}", server_handshake);
}
