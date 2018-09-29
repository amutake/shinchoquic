extern crate aes_ctr;
#[macro_use]
extern crate hex_literal;
extern crate byteorder;
extern crate crypto as rust_crypto;
extern crate rand;
extern crate ring;
extern crate rustls;
extern crate untrusted;
extern crate webpki;
extern crate webpki_roots;

use rustls::quic::{ClientQuicExt, Keys, QuicExt, Side};
use rustls::suites::TLS13_AES_128_GCM_SHA256;
use rustls::{ClientConfig, ClientSession, ProtocolVersion, Session, SupportedCipherSuite};
use std::fs::File;
use std::io::Read;
use std::net;
use std::sync::Arc;
use webpki::trust_anchor_util::cert_der_as_trust_anchor;
use webpki::{DNSNameRef, TLSServerTrustAnchors};
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
    let mut crt = vec![];
    File::open("./quinn.der")
        .expect("failed to open ./ca.crt")
        .read_to_end(&mut crt)
        .expect("failed to read ./ca.crt");

    let root = cert_der_as_trust_anchor(untrusted::Input::from(&crt))
        .expect("failed to read as trust anchor");

    let mut config = ClientConfig::new();
    config.ciphersuites = vec![&TLS13_AES_128_GCM_SHA256]; // TODO
    config.versions = vec![ProtocolVersion::TLSv1_3];
    config.alpn_protocols = vec!["hq-14".into()];
    config
        .root_store
        .add_server_trust_anchors(&TLSServerTrustAnchors(&[root]));

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
    let crypto_offset = crypto.len();
    let packet = packet::Packet::Initial {
        version: 0xff00000e,
        dst_conn_id,
        src_conn_id: src_conn_id.clone(), // TODO
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
    socket
        .send_to(&client_initial, "127.0.0.1:4433")
        .expect("failed to send client initial packet");

    // recv server initial + handshake
    let mut buf = [0; 1500];
    let (amt, _) = socket
        .recv_from(&mut buf)
        .expect("failed to recv server Initial + Handshake packet");
    let buf = &buf[..amt];
    let (server_initial, amt) =
        packet::Packet::decode(&buf, &keys).expect("failed to decode server Initial packet");
    println!("server initial: {:?}", server_initial);
    let buf = &buf[amt..];

    let crypto = match server_initial {
        packet::Packet::Initial { ref payload, .. } => match payload.frames.get(1) {
            // TODO: offset もちゃんと扱う
            Some(packet::Frame::Crypto { payload, .. }) => payload,
            _ => panic!("server initial frame[1] must be a CRYPTO frame"),
        },
        _ => panic!("first packet from server must be an Initial packet"),
    };
    let dst_conn_id = match server_initial {
        packet::Packet::Initial { src_conn_id, .. } => src_conn_id,
        _ => panic!("first packet from server must be an Initial packet"),
    };

    session.read_hs(&crypto).unwrap();
    match session.get_handshake_keys() {
        Some(handshake_keys) => {
            keys.set_handshake(handshake_keys);
        }
        _ => panic!("failed to get handshake keys"),
    }

    // server handshake
    let (server_handshake, amt) =
        packet::Packet::decode(&buf, &keys).expect("failed to decode server handshake packet");
    println!("server handshake: {:?}", server_handshake);
    let buf = &buf[amt..];

    let crypto = match server_handshake {
        packet::Packet::Handshake { ref payload, .. } => match payload.frames.get(0) {
            Some(packet::Frame::Crypto { payload, .. }) => payload,
            _ => panic!("server handshake frame[0] must be a CRYPTO frame"),
        },
        _ => panic!("second packet from server must be an Handshake packet"),
    };
    util::print_hex("CRYPTO 1", &crypto);
    session.read_hs(&crypto).unwrap();

    assert!(buf.is_empty());

    // recv server handshake 2
    let mut buf = [0; 1500];
    let (amt, _) = socket
        .recv_from(&mut buf)
        .expect("failed to recv server Handshake packet");
    let buf = &buf[..amt];

    let (server_handshake, amt) =
        packet::Packet::decode(&buf, &keys).expect("failed to decode server handshake packet");
    println!("server handshake: {:?}", server_handshake);
    let buf = &buf[amt..];

    let crypto = match server_handshake {
        packet::Packet::Handshake { ref payload, .. } => match payload.frames.get(0) {
            Some(packet::Frame::Crypto { payload, .. }) => payload,
            _ => panic!("server handshake frame[0] must be a CRYPTO frame"),
        },
        _ => panic!("second packet from server must be an Handshake packet"),
    };
    util::print_hex("CRYPTO 2", &crypto);
    session.read_hs(&crypto).unwrap();

    // server handshake 3
    if buf.is_empty() {
        println!("EmPTYTYTY");
    }

    let mut buf = [0; 1500];
    let (amt, _) = socket
        .recv_from(&mut buf)
        .expect("failed to recv server Handshake packet");
    let buf = &buf[..amt];

    let (server_handshake, amt) =
        packet::Packet::decode(&buf, &keys).expect("failed to decode server handshake packet");
    println!("server handshake: {:?}", server_handshake);
    let buf = &buf[amt..];

    let crypto = match server_handshake {
        packet::Packet::Handshake { ref payload, .. } => match payload.frames.get(0) {
            Some(packet::Frame::Crypto { payload, .. }) => payload,
            _ => panic!("server handshake frame[0] must be a CRYPTO frame"),
        },
        _ => panic!("second packet from server must be an Handshake packet"),
    };
    util::print_hex("CRYPTO 3", &crypto);
    session.read_hs(&crypto).unwrap();

    // server handshake 4
    if buf.is_empty() {
        println!("EmPTYTYTY");
    }

    let mut buf = [0; 1500];
    let (amt, _) = socket
        .recv_from(&mut buf)
        .expect("failed to recv server Handshake packet");
    let buf = &buf[..amt];

    let (server_handshake, amt) =
        packet::Packet::decode(&buf, &keys).expect("failed to decode server handshake packet");
    println!("server handshake: {:?}", server_handshake);
    let buf = &buf[amt..];

    let crypto = match server_handshake {
        packet::Packet::Handshake { ref payload, .. } => match payload.frames.get(0) {
            Some(packet::Frame::Crypto { payload, .. }) => payload,
            _ => panic!("server handshake frame[0] must be a CRYPTO frame"),
        },
        _ => panic!("second packet from server must be an Handshake packet"),
    };
    util::print_hex("CRYPTO 4", &crypto);
    session.read_hs(&crypto).unwrap();

    // HANDSHAKE FINISHED
    match session.get_1rtt_keys() {
        Some(one_rtt_keys) => {
            util::print_hex("1rtt write key", &one_rtt_keys.write_key);
            keys.set_one_rtt(one_rtt_keys);
        }
        _ => panic!("failed to get handshake keys"),
    }

    // ACK Initial(0)
    let packet = packet::Packet::Initial {
        version: 0xff00000e,
        dst_conn_id: dst_conn_id.clone(), // TODO
        src_conn_id: src_conn_id.clone(), // TODO
        token: vec![],
        packet_number: pn_spaces.next_initial(),
        payload: packet::Payload {
            frames: vec![packet::Frame::Ack {
                largest: 0,
                delay: 0,
                blocks: AckBlocks {
                    first: 0,
                    additional: vec![],
                },
            }],
        },
    };
    let mut buf = [0; 1500];
    let amt = packet
        .encode(&keys, &mut buf)
        .expect("failed to encode client initial ack packet");
    let client_initial = &buf[..amt];
    util::print_hex("client initial", &client_initial);
    socket
        .send_to(&client_initial, "127.0.0.1:4433")
        .expect("failed to send client initial packet");

    // FIN
    let mut crypto = vec![];
    session.write_hs(&mut crypto);
    util::print_hex("CRYPTO", &crypto);
    let packet = packet::Packet::Handshake {
        version: 0xff00000e,
        dst_conn_id,
        src_conn_id,
        packet_number: pn_spaces.next_handshake(),
        payload: packet::Payload {
            frames: vec![
                packet::Frame::Ack {
                    largest: 3,
                    delay: 0,
                    blocks: AckBlocks {
                        first: 3,
                        additional: vec![],
                    },
                },
                packet::Frame::Crypto {
                    offset: 0, // encryption level が変わると offset が 0 になる！
                    payload: crypto,
                },
            ],
        },
    };
    let mut buf = [0; 1500];
    let amt = packet
        .encode(&keys, &mut buf)
        .expect("failed to encode client handshake packet");
    let client_initial = &buf[..amt];
    util::print_hex("client handshake", &client_initial);
    socket
        .send_to(&client_initial, "127.0.0.1:4433")
        .expect("failed to send client handshake packet");

    // server ACK
    let mut buf = [0; 1500];
    let (amt, _) = socket
        .recv_from(&mut buf)
        .expect("failed to recv server Handshake packet");
    let buf = &buf[..amt];

    let (server_handshake, amt) =
        packet::Packet::decode(&buf, &keys).expect("failed to decode server handshake packet");
    println!("server handshake: {:?}", server_handshake);
    let buf = &buf[amt..];

    // server 1RTT APP DATA
    let mut buf = [0; 1500];
    let (amt, _) = socket
        .recv_from(&mut buf)
        .expect("failed to recv server 1RTT packet");
    let buf = &buf[..amt];
    util::print_hex("1rtt", &buf);

    let (server_1rtt, amt) =
        packet::Packet::decode(&buf, &keys).expect("failed to decode server 1RTT packet");
    println!("server 1rtt: {:?}", server_1rtt);
    let buf = &buf[amt..];
}
