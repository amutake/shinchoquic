use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewFixStreamCipher, StreamCipherCore};
use aes_ctr::Aes128Ctr;
use byteorder::{ByteOrder, NetworkEndian};
use rand::{thread_rng, Rng};
use ring::aead;
use rust_crypto::aead::AeadEncryptor;
use rust_crypto::aes::KeySize;
use rust_crypto::aes_gcm::AesGcm;
use rustls::quic::{ClientQuicExt, Keys, QuicExt, Side};
use rustls::suites::TLS13_AES_128_GCM_SHA256;
use rustls::Session;
use rustls::{ClientConfig, ClientSession, ProtocolVersion, SupportedCipherSuite};
use std::sync::Arc;
use webpki::DNSNameRef;
use webpki_roots;

use util;

const CONN_ID_LEN: usize = 18;

fn fill_random(buf: &mut [u8]) {
    thread_rng().fill(buf);
}

fn print_client_config(c: &ClientConfig) {
    println!("ClientConfig {{");
    println!("  ciphersuites: {:?}", c.ciphersuites);
    println!("  alpn_protocols: {:?}", c.alpn_protocols);
    println!("  versions: {:?}", c.versions);
    println!("}}");
}

fn variable_length_integer(n: u64, buf: &mut [u8]) -> usize {
    // なぜ buf: &mut [u8] を取るか？
    // なぜ Vec<u8> を返さないか？
    // => byteorder が Read/Write のインタフェースっぽくなっている
    // Vec だと、一旦中で mut slice を作って、書き込んで、vec に変換して、サイズを調整して、返す
    // それなら buf もらって、書き込んで、サイズを返したほうがコード量少なくなる
    if n <= 0b0011_1111 {
        buf[0] = n as u8;
        1
    } else if n <= 0b0011_1111_1111_1111 {
        NetworkEndian::write_u16(buf, (1u16 << 14) ^ (n as u16));
        2
    } else if n <= 0b0011_1111_1111_1111_1111_1111_1111_1111 {
        NetworkEndian::write_u32(buf, (2u32 << 30) ^ (n as u32));
        4
    } else if n <= 0b0011_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111
    {
        NetworkEndian::write_u64(buf, (3u64 << 62) ^ n);
        8
    } else {
        panic!("variable length integer too large: {}", n);
    }
}

pub fn client_initial_packet(dst_conn_id: &[u8], src_conn_id: &[u8], crypto: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();

    // long header, initial
    buf.push(0xff);
    // version
    buf.extend_from_slice(&hex!("ff00000e"));
    // DCIL & SCIL
    let dcil = if dst_conn_id.len() == 0 {
        0
    } else {
        dst_conn_id.len() as u8 - 3
    };
    let scil = if src_conn_id.len() == 0 {
        0
    } else {
        src_conn_id.len() as u8 - 3
    };
    buf.push((dcil << 4) + scil);
    // dst conn id
    buf.extend_from_slice(dst_conn_id);
    // src conn id
    buf.extend_from_slice(src_conn_id);
    // token length
    buf.push(0);
    // token
    // (empty)

    // build payload
    let mut payload = vec![];
    payload.push(0x18); // Type: CRYPTO
    payload.push(0x00); // Offset: 0
    let mut varbuf = [0; 8];
    let amt = variable_length_integer(crypto.len() as u64, &mut varbuf);
    let mut v = varbuf[..amt].to_vec();
    payload.append(&mut v);
    payload.extend_from_slice(crypto);
    if payload.len() + buf.len() < 1200 {
        let padding_len = 1200 - payload.len();
        payload.append(&mut vec![0; padding_len]); // initial packet は 1200 以上必要なため
    }

    // length
    let length = 1 + payload.len() + 16; // 1 is PN, 16 is authentication tag
    let amt = variable_length_integer(length as u64, &mut varbuf);
    let mut v = varbuf[..amt].to_vec();
    buf.append(&mut v);

    // packet number
    let pn_offset = buf.len(); // 後で使う
    let full_pn = 0u64;
    buf.push(full_pn as u8); // パケット番号のエンコーディングはだるいので 1-byte 固定

    // payload encryption
    let initial_keys = Keys::initial(&dst_conn_id, Side::Client);
    let ad = &buf.clone()[..]; // TODO
    let nonce = util::xor(
        &initial_keys.write_iv,
        &util::left_pad(&[full_pn as u8], initial_keys.write_iv.len())[..],
    );
    let key = aead::SealingKey::new(&aead::AES_128_GCM, &initial_keys.write_key).unwrap();
    // TODO
    util::print_hex("payload", &payload);
    util::print_hex("key", &initial_keys.write_key);
    util::print_hex("nonce", &nonce);
    util::print_hex("ad", ad);
    let mut test = [0; 100];
    aead::seal_in_place(&key, &nonce, ad, &mut test[..], 16).expect("encryption error test");
    util::print_hex("test", &test);

    let mut aes_gcm = AesGcm::new(KeySize::KeySize128, &initial_keys.write_key, &nonce, ad);
    let mut payload_buf = vec![0; payload.len()];
    let mut tag = [0; 16];
    aes_gcm.encrypt(&payload, &mut payload_buf, &mut tag);
    payload_buf.extend_from_slice(&tag);
    let mut payload = payload_buf;

    // packet number encryption
    let sample = &payload.clone()[3..19]; // パケット番号は本当は1バイトだけど4バイトとして見る
    let key = GenericArray::from_slice(&initial_keys.write_pn);
    let nonce = GenericArray::from_slice(sample);
    let mut cipher = Aes128Ctr::new(&key, &nonce);
    let mut encrypted_pn = [full_pn as u8];
    cipher.apply_keystream(&mut encrypted_pn);

    buf[pn_offset] = encrypted_pn[0];
    util::print_hex("buf", &buf);
    util::print_hex("encrypted payload", &payload);

    //
    buf.append(&mut payload);

    buf
}

pub fn main() {
    let mut config = ClientConfig::new();
    print_client_config(&config);
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

    // let mut dst_conn_id = [0; CONN_ID_LEN];
    // fill_random(&mut dst_conn_id);
    let dst_conn_id = hex!("f2aca972962edd0f195aa1bb9a16734be91b");
    // let mut src_conn_id = [0; CONN_ID_LEN];
    // fill_random(&mut src_conn_id);
    let src_conn_id = hex!("d545b3713ec650dc4844f59652f737fa3a");

    let mut crypto = vec![];
    session.write_hs(&mut crypto);
    util::print_hex("crypto", &crypto);
    // let crypto = hex!("010001270303ec616ce0718ff6cc0beef7fd70d3e2cfa791b9d8a78ba9d4acae89e58d99e11c00000813021303130100ff010000f6ffa50038ff00000e003200030002001e0000000400040000000a000400040000000b00040004000000010004001000000002000200010008000200010000000e000c0000096c6f63616c686f7374000b000403000102000a000a00080017001d00180019002300000010000800060568712d31340016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d0002010100330047004500170041048f5a12125ccca5667935e64dd2b9923b0df1c97e3d3212dc5b4aa7b036ef0faec05aeac66fe0866d9de85fae29960d954baf81ec68e3619a0712393e14945422000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    println!("crypto.len: {}", crypto.len());
    let packet = client_initial_packet(&dst_conn_id, &src_conn_id, &crypto);
    util::print_hex("initial packet", &packet);
    use ngtcp2;
    ngtcp2::decode_print(ngtcp2::Side::Client, &packet);

    use std::net;

    let socket = net::UdpSocket::bind("0.0.0.0:0").unwrap();

    socket.send_to(&packet, "localhost:4433").unwrap();
    let mut buf = [0; 1500];
    let (amt, _) = socket.recv_from(&mut buf).unwrap();
    let payload = ngtcp2::decode_print(ngtcp2::Side::Server, &buf[..amt]);

    session.read_hs(&payload[9..]).unwrap();

    let mut crypto = vec![];

    session.write_hs(&mut crypto);
    // session.write_hs(&mut crypto);

    util::print_hex("crypto", &crypto);
}
