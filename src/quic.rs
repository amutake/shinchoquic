use rustls::quic::{ClientQuicExt, QuicExt, Keys, Side};
use rustls::{ClientSession, ClientConfig, ProtocolVersion, SupportedCipherSuite};
use rustls::suites::TLS13_AES_128_GCM_SHA256;
use std::sync::Arc;
use rand::{thread_rng, Rng};
use webpki::DNSNameRef;

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
    // config.ciphersuites = vec![&TLS13_AES_128_GCM_SHA256];
    config.versions = vec![ProtocolVersion::TLSv1_3];

    let config = Arc::new(config);
    let params = vec![];
    let hostname = DNSNameRef::try_from_ascii_str("localhost").unwrap();
    let session = ClientSession::new_quic(&config, hostname, params);

    let mut dst_conn_id = [0; CONN_ID_LEN];
    fill_random(&mut dst_conn_id);
    let initial_keys = Keys::initial(&dst_conn_id, Side::Client);
    println!("{:?}", initial_keys);
}
