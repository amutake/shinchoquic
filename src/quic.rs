use rand::{thread_rng, Rng};
use rustls::quic::{ClientQuicExt, Keys, QuicExt, Side};
use rustls::suites::TLS13_AES_128_GCM_SHA256;
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

pub fn main() {
    let mut config = ClientConfig::new();
    print_client_config(&config);
    config.ciphersuites = vec![&TLS13_AES_128_GCM_SHA256];
    config.versions = vec![ProtocolVersion::TLSv1_3];
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let config = Arc::new(config);
    let params = vec![];
    let hostname = DNSNameRef::try_from_ascii_str("localhost").unwrap();
    let session = ClientSession::new_quic(&config, hostname, params);

    // let mut dst_conn_id = [0; CONN_ID_LEN];
    // fill_random(&mut dst_conn_id);
    let dst_conn_id = hex!("f2aca972962edd0f195aa1bb9a16734be91b");
    let initial_keys = Keys::initial(&dst_conn_id, Side::Client);

    util::print_hex("client_pp_key", &initial_keys.write_key[..]);
    util::print_hex("client_pp_iv", &initial_keys.write_iv[..]);
    util::print_hex("client_pp_pn", &initial_keys.write_pn[..]);
}
