use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewFixStreamCipher, StreamCipherCore};
use aes_ctr::*;
use ring::aead;
use std::io::Write;

fn hex_to_string(hex: &[u8]) -> String {
    let mut w = Vec::new();
    write!(&mut w, "0x").unwrap();
    for b in hex.iter() {
        write!(&mut w, "{:02x}", b).unwrap();
    }
    String::from_utf8(w).unwrap()
}

fn print_hex(key: &'static str, hex: &[u8]) {
    println!("{}: {}", key, hex_to_string(hex));
}

fn xor(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    assert_eq!(lhs.len(), rhs.len());
    lhs.iter().zip(rhs.iter()).map(|(l, r)| l ^ r).collect()
}

fn decrypt_pp_pn<'a>(pn_key: &[u8], sample: &[u8], text: &'a mut [u8]) -> &'a [u8] {
    let key = GenericArray::from_slice(pn_key);
    let nonce = GenericArray::from_slice(sample);
    let mut cipher = Aes128Ctr::new(&key, &nonce);
    cipher.apply_keystream(text);
    pn_strip(text)
}

fn decrypt_hs_pn<'a>(pn_key: &[u8], sample: &[u8], text: &'a mut [u8]) -> &'a [u8] {
    let key = GenericArray::from_slice(pn_key);
    let nonce = GenericArray::from_slice(sample);
    let mut cipher = Aes256Ctr::new(&key, &nonce);
    cipher.apply_keystream(text);
    pn_strip(text)
}

fn left_pad(a: &[u8], len: usize) -> Vec<u8> {
    let alen = a.len();
    assert!(len >= alen);
    let mut v = vec![0; len - alen];
    v.append(&mut a.to_vec());
    v
}

fn pn_strip(pn: &[u8]) -> &[u8] {
    assert_eq!(pn.len(), 4);
    if (pn[0] >> 7) == 0 {
        &pn[..1]
    } else if (pn[0] >> 6) == 2 {
        &pn[..2]
    } else {
        pn
    }
}

fn decrypt_pp_payload<'a>(
    key: &[u8],
    iv: &[u8],
    pn: &[u8],
    ad: &[u8],
    payload: &'a mut [u8],
) -> &'a mut [u8] {
    let nonce = xor(iv, &left_pad(pn, iv.len())[..]);
    let key = aead::OpeningKey::new(&aead::AES_128_GCM, key).unwrap();
    aead::open_in_place(&key, &nonce[..], ad, 0, payload).unwrap()
}

fn decrypt_hs_payload<'a>(
    key: &[u8],
    iv: &[u8],
    pn: &[u8],
    ad: &[u8],
    payload: &'a mut [u8],
) -> &'a mut [u8] {
    let nonce = xor(iv, &left_pad(pn, iv.len())[..]);
    let key = aead::OpeningKey::new(&aead::AES_256_GCM, key).unwrap();
    aead::open_in_place(&key, &nonce[..], ad, 0, payload).unwrap()
}

#[derive(Debug)]
pub enum Side {
    Client,
    Server,
}

// これどうにかしたい
fn decode_variable_length_integer(v: &[u8]) -> (u64, usize) {
    let mlb = v[0] >> 6;
    if mlb == 0 {
        (v[0] as u64, 1)
    } else if mlb == 1 {
        ((((v[0] & 0b0011_1111) as u64) << 8) + (v[1] as u64), 2)
    } else if mlb == 2 {
        (
            (((v[0] & 0b0011_1111) as u64) << 24)
                + ((v[1] as u64) << 16)
                + ((v[2] as u64) << 8)
                + (v[3] as u64),
            4,
        )
    } else {
        (
            (((v[0] & 0b0011_1111) as u64) << 56)
                + ((v[1] as u64) << 48)
                + ((v[2] as u64) << 40)
                + ((v[3] as u64) << 32)
                + ((v[4] as u64) << 24)
                + ((v[5] as u64) << 16)
                + ((v[6] as u64) << 8)
                + (v[7] as u64),
            8,
        )
    }
}

pub fn decode_print(sender: Side, packet: &[u8]) -> Vec<u8> {
    println!("========= sender: {:?} ========", sender);
    print_hex("original", &packet);
    println!("========= sender: {:?} ========", sender);
    if packet[0] >> 7 == 1 {
        // long header
        if packet[0] & 0b0111_1111 == 0x7f {
            // initial packet
            println!("Type: Initial");
            // version
            print_hex("Version: ", &packet[1..5]);
            // DCIL
            let dcil = (packet[5] >> 4) + 3;
            println!("DCIL: {}", dcil);
            // SCIL
            let scil = (packet[5] & 0b0000_1111) + 3;
            println!("SCIL: {}", scil);
            // Dst Conn ID
            let offset = 6;
            let dst_conn_id = &packet[offset..(offset + dcil as usize)];
            print_hex("Dst Connection ID", &dst_conn_id);
            let offset = offset + dcil as usize;
            // Src Conn ID
            let src_conn_id = &packet[offset..(offset + scil as usize)];
            print_hex("Src Connection ID", &src_conn_id);
            let offset = offset + scil as usize;
            // Token Length
            let (token_len, amt) = decode_variable_length_integer(&packet[offset..]);
            println!("Token Length: {}", token_len);
            let offset = offset + amt;
            // Token
            let token = &packet[offset..(offset + token_len as usize)];
            print_hex("Token", &token);
            let offset = offset + token_len as usize;
            // Length
            let (length, amt) = decode_variable_length_integer(&packet[offset..]);
            println!("Length: {}", length);
            let offset = offset + amt;

            match sender {
                Side::Client => {
                    let client_pp_pn = hex!("00d89d6dc887026d10bbe7892567d9d0");
                    let client_pp_iv = hex!("d4213359165f5e1caf724ce6");
                    let client_pp_key = hex!("541b8a1e19e5db40fbfa6b345cbdfb45");
                    // Packet Number
                    let mut pn = [0; 4];
                    pn.copy_from_slice(&packet[offset..(offset + 4)]);
                    let sample = &packet[(offset + 4)..(offset + 4 + 16)];
                    let pn = decrypt_pp_pn(&client_pp_pn, &sample, &mut pn);
                    print_hex("Packet Number", &pn);
                    let amt = pn.len();
                    // Payload
                    let mut ad = packet[..offset].to_vec();
                    ad.extend_from_slice(&pn);
                    let mut payload = packet[offset + amt..offset + length as usize].to_vec();
                    let mut payload = payload.as_mut_slice();
                    let payload =
                        decrypt_pp_payload(&client_pp_key, &client_pp_iv, &pn, &ad, &mut payload);
                    print_hex("Payload", &payload);
                    payload.to_vec()
                }
                Side::Server => {
                    let server_pp_pn = hex!("49eb3707f0dfb919df2cafdf2c7f712f");
                    let server_pp_iv = hex!("7cff52a51c5db4b7be35ff54");
                    let server_pp_key = hex!("65f61c23ea93104df46e698817326abb");
                    // Packet Number
                    let mut pn = [0; 4];
                    pn.copy_from_slice(&packet[offset..(offset + 4)]);
                    let sample = &packet[(offset + 4)..(offset + 4 + 16)];
                    let pn = decrypt_pp_pn(&server_pp_pn, &sample, &mut pn);
                    print_hex("Packet Number", &pn);
                    let amt = pn.len();
                    // Payload
                    let mut ad = packet[..offset].to_vec();
                    ad.extend_from_slice(&pn);
                    let mut payload = packet[offset + amt..offset + length as usize].to_vec();
                    print_hex(
                        "next packet",
                        &packet[offset + length as usize..offset + length as usize + 32],
                    );
                    let mut payload = payload.as_mut_slice();
                    let payload =
                        decrypt_pp_payload(&server_pp_key, &server_pp_iv, &pn, &ad, &mut payload);
                    print_hex("Payload", &payload);
                    payload.to_vec()
                }
            }
        } else if packet[0] & 0b0111_1111 == 0x7d {
            // handshake packet
            println!("Type: Handshake");
            // version
            print_hex("Version: ", &packet[1..5]);
            // DCIL
            let dcil = (packet[5] >> 4) + 3;
            println!("DCIL: {}", dcil);
            // SCIL
            let scil = (packet[5] & 0b0000_1111) + 3;
            println!("SCIL: {}", scil);
            // Dst Conn ID
            let offset = 6;
            let dst_conn_id = &packet[offset..(offset + dcil as usize)];
            print_hex("Dst Connection ID", &dst_conn_id);
            let offset = offset + dcil as usize;
            // Src Conn ID
            let src_conn_id = &packet[offset..(offset + scil as usize)];
            print_hex("Src Connection ID", &src_conn_id);
            let offset = offset + scil as usize;
            // Token Length
            let (token_len, amt) = decode_variable_length_integer(&packet[offset..]);
            println!("Token Length: {}", token_len);
            let offset = offset + amt;

            match sender {
                Side::Client => {
                    let client_hs_key =
                        hex!("223eb924c5f42ed9ef2579a397d67062d1be55928c1fedd6629a9101ca75dddc");
                    let client_hs_iv = hex!("97228ab773f2d8e25f0f7ddd");
                    let client_hs_pn =
                        hex!("9db32f66578541b9bcc6482aefff89fb17e660b736dbf9133e4035bb314bba86");
                    // Packet Number
                    let mut pn = [0; 4];
                    pn.copy_from_slice(&packet[offset..(offset + 4)]);
                    let sample = &packet[(offset + 4)..(offset + 4 + 16)];
                    let pn = decrypt_hs_pn(&client_hs_pn, &sample, &mut pn);
                    print_hex("Packet Number", &pn);
                    let amt = pn.len();
                    // Payload
                    let mut ad = packet[..offset].to_vec();
                    ad.extend_from_slice(&pn);
                    let mut payload = packet[offset + amt..].to_vec();
                    let mut payload = payload.as_mut_slice();
                    let payload =
                        decrypt_hs_payload(&client_hs_key, &client_hs_iv, &pn, &ad, &mut payload);
                    print_hex("Payload", &payload);
                    payload.to_vec()
                }
                Side::Server => {
                    let server_hs_key =
                        hex!("e23cad831aaf559eadc0f61462fe607d13171a75908a4844a1ad45d51da98ab9");
                    let server_hs_iv = hex!("7c62db0886e08b4741295942");
                    let server_hs_pn =
                        hex!("bf5279851c8961d753aaff79e64b095001e428c661019ce98beeebcb1ec7ef63");
                    // Packet Number
                    let mut pn = [0; 4];
                    pn.copy_from_slice(&packet[offset..(offset + 4)]);
                    let sample = &packet[(offset + 4)..(offset + 4 + 16)];
                    let pn = decrypt_hs_pn(&server_hs_pn, &sample, &mut pn);
                    print_hex("Packet Number", &pn);
                    let amt = pn.len();
                    // Payload
                    let mut ad = packet[..offset].to_vec();
                    ad.extend_from_slice(&pn);
                    let mut payload = packet[offset + amt..].to_vec();
                    let mut payload = payload.as_mut_slice();
                    let payload =
                        decrypt_hs_payload(&server_hs_key, &server_hs_iv, &pn, &ad, &mut payload);
                    print_hex("Payload", &payload);
                    payload.to_vec()
                }
            }
        } else {
            panic!("packet type not supported");
        }
    } else {
        // short header
        // Key Phase Bit
        let key_phase = (packet[0] & 0b0100_0000) >> 6;
        println!("Key Phase Bit: {}", key_phase);
        // Third Bit
        let third = (packet[0] & 0b0010_0000) >> 5;
        println!("Third Bit: {}", third);
        // Fourth Bit
        let fourth = (packet[0] & 0b0001_0000) >> 4;
        println!("Fourth Bit: {}", fourth);
        // Google QUIC Demultiplexing Bit
        let google = (packet[0] & 0b0000_1000) >> 3;
        println!("Google QUIC Demultiplexing Bit: {}", google);
        // Reserved
        let reserved = packet[0] & 0b0000_0111;
        println!("Reserved: {}", reserved);

        let mut offset = 1;
        // dst_conn_id の長さを知ってる前提
        match sender {
            Side::Client => {
                // Dst Conn ID (18)
                let dst_conn_id = &packet[offset..(offset + 18)];
                print_hex("Dst Connection ID", &dst_conn_id);
                offset += 18;
                //
                let client_ap_key =
                    hex!("7dae294fd8bb4264b985082afc8f19571810e72ff7f61427ab239017b06d4542");
                let client_ap_iv = hex!("0c5b8b38e76512e6a20857a4");
                let client_ap_pn =
                    hex!("2a50a23b75bd70afa9566830b56113422b83bc2475b8696ad8d8938adffdc6a1");
                // Packet Number
                let mut pn = [0; 4];
                pn.copy_from_slice(&packet[offset..(offset + 4)]);
                let sample = &packet[(offset + 4)..(offset + 4 + 16)];
                let pn = decrypt_hs_pn(&client_ap_pn, &sample, &mut pn);
                print_hex("Packet Number", &pn);
                let amt = pn.len();
                // Payload
                let mut ad = packet[..offset].to_vec();
                ad.extend_from_slice(&pn);
                let mut payload = packet[offset + amt..].to_vec();
                let mut payload = payload.as_mut_slice();
                let payload =
                    decrypt_hs_payload(&client_ap_key, &client_ap_iv, &pn, &ad, &mut payload);
                print_hex("Payload", &payload);
                payload.to_vec()
            }
            Side::Server => {
                // Dst Conn ID (17)
                let dst_conn_id = &packet[offset..(offset + 17)];
                print_hex("Dst Connection ID", &dst_conn_id);
                offset += 17;
                //
                let server_ap_key =
                    hex!("13cfbc7d41fd53f2228f529cbadc2e8bb3bb70d5c2dbac03fae02c63248d77c8");
                let server_ap_iv = hex!("3316b6c7d4b85cf5bcb3fbf5");
                let server_ap_pn =
                    hex!("337940cda868c035431596f366ca4fc00a1008f92013c4364c0f5d2d97b1ca8d");
                // Packet Number
                let mut pn = [0; 4];
                pn.copy_from_slice(&packet[offset..(offset + 4)]);
                let sample = &packet[(offset + 4)..(offset + 4 + 16)];
                let pn = decrypt_hs_pn(&server_ap_pn, &sample, &mut pn);
                print_hex("Packet Number", &pn);
                let amt = pn.len();
                // Payload
                let mut ad = packet[..offset].to_vec();
                ad.extend_from_slice(&pn);
                let mut payload = packet[offset + amt..].to_vec();
                let mut payload = payload.as_mut_slice();
                let payload =
                    decrypt_hs_payload(&server_ap_key, &server_ap_iv, &pn, &ad, &mut payload);
                print_hex("Payload", &payload);
                payload.to_vec()
            }
        }
    }
}

pub fn main() {
    decode_print(Side::Client, &hex!("ffff00000efef2aca972962edd0f195aa1bb9a16734be91bd545b3713ec650dc4844f59652f737fa3a0044b87dfea45b7951caaea8aed9134aa73c600b6ae087ab834698b8722666cf1bb1fc785d9fd1ad74f95f0ee146c339af282a03f95181fe520785637467a3f44c7e756c74df109204bd51a4ec596edded9aedf2d0bd3a1f83a1244faf83dbc2be1aa9f278aba4fcfb28bca83e5f34b0ad117eb062db68d0df7f80b3ffbd49970452f110a0629029d12836bf93b749d4ef3f9c178d5de4748ea5e1eb91342a41419d781d27b0a4238966d4234b503df94c3da0942c0f7add1d6c69b52829a31bc693eeeae14dd33323b573d5de3756ea2b9a3c358164db6932e0f50ec61be4f00fc01de7776260afa0ed36699ada8601a229058359b6010dcb74c2bee3ebfa41539b3285aa135c341e8755c2ab445a4d0fe5721f59068835222a93bcf3e340ca103fbc514f5ebe55381e0f4f8c45b2400d1335246960236170b5e61850e3b60cd150f205d3f264a034dd0a53eae40534ff48aee5f18fa5a3c9b49bb50913894fa15335efc6b7f50d63361c04565b2647650f3d0adc67e84a45378bb143156a2ebaa0e0f7f16fd1ccc9cc596685afce902d6c6bf6ae753863332e949c70be2e255a848bace872c2163a2890e5145d9dad6e2843b0bfad09551b5dbb259863249a1ec1aff33bb36ac9373b0506d246b69f0bc1f64340008d15263e36838b06042b36c319897265faa3b70460e5e65347f55aae04ec07a7b0e83c20bb0a466a6b46b6cbc4716f9abe3b463c5a14b7e849fa790917b9f41fcd1443b0a2dcd48e9b8f809f8d49445962b483ad198f55043d0488f16f87ce528a5305dbe97eafd525907bcd69ab3fca3b0f10b3197b257ac0c2fa423f2232ee4525fab817d42f6546b569aa4568b9ab3fd24b453963c6969b57fb265b00034b4a096530570f0d7a56e439bfa1c13db07fb3c686d753144781185418b71b9394ef9345aa42ffc6ba8633342aee2da200b61699764dae176738ebadc71ecd1ecbc6b9d8c19b272414c9a413fa18680f96713a175a2334422fe6a49865a32855caadca58272ba8eea41cc96c166f71897367079ab44994fb3ef975a1b02eb89b3c5f97dbb01820be655f8dbf062ba9e09b3c3c59e1a28e138607daf3a8ff45d60d6f878cabc8d9beead0608a019a9b4e7518e1ec873c72ffd8015c5a719299857968c06819d03168cdca67ecfe8861e68f7f846abfe5deecdda45b8d7da36def9fdf67e539d841008d8281213b605ca01fd7026f26a99497cf7dc708f4d4054c1f6de935707acb6764997f218dc372283bf56d7296f16dd8d976a648dbcc6e9457d3ad13ea04aef46ee5682352c083aabc7882406e8064949473616d13e42cea842d193d20bb2ca2af87a19586dc68a558f0d629873cec3d61970434e72e6246f197840afe324e8ce299ee8d19c7178195d5f762efdee05f4efbfe90bc48e5d8d01d0e1a62a5ec997cf056301126c65c4d1aee9f5e3f5aa529b3265f2483b8b474179f4b77db6b4b732d0c309ddc6b9d6dccac9eb3c23ed0619a5b2c04841ac033705fc3ced733e87ad7ce1eb7692a67732e893457385802f5f62f6eca60033778e35d02286b6d4b5ab579fd15a4043481981010efc3b3504344e793330aaf5f7801fb66da2346d4d2ecea2f1e8f7d93cad68d0eec4e111a2e4c4a65199826904a1da4d17dd78a4fd28d97ad29c0bfd058fb3e1207c63cdd02f95ae4838e1b335fe9f0b6da31"));
    // decode_print(Side::Server, &hex!("ffff00000eefd545b3713ec650dc4844f59652f737fa3a06d365c2a77f84da934dbf7436bfd74a72d700409577e24ec34249d9b74de91a153bb6aaf898240938067b28b0c96e84afa475ffe1cb457a9700a4dc2dc36beefdbf6202b3251fadb3216e9bbe3157f55f045c59a358b8e645b3f618d85695dd3a25b7560e36b7464bb6ff1624103c94e509fae29a8c88caf11f9f905af072b759033c8bcf2411fea5dd637ae28b3725b3a9de8de5bbc1971aee03f98c629017d423603593274cd3223f"));
    // decode_print(Side::Server, &hex!("fdff00000eefd545b3713ec650dc4844f59652f737fa3a06d365c2a77f84da934dbf7436bfd74a72d743ebf2576c0aed4150a630626d537a43b5e3a33dcdf368a2ddd9c27386f571efa87c5e1f20aff1fb6f18681e52ea6ef7467974b2bb74153d41099bbe3f188cf36c79422d752f2300153be9ee1060b049f5f7b189e6074479d9bdf2d0ba9fb29c3f4a07e52d2089e098ec607b8ed433fe742b73dec8baeed048b251d02bd00d38a609897d0d02733b5fd6ebcfac3e7398a84bf824c96caa9ba370407969a2bbd457d470ff9eecd9391af412482fbaf100d3645129fbbf507c5068651e18d8e5f7a5198604af9e6eea3adfca8d2930b30e4cb59e7fa0233018edba7d582627bcaa62f2b3b1e745d873fbc46c79157f6b9a569ffe476dffd2f53244594e6bcc148705cf4d9a4f03b4fb04a9f41bcce4f8992a229bd32f710184cb995942775f56942243678b81c437dfe2a86d748a853261ad00698028f4607d50329d1383df1508c1f9f34cad92756a540e5c38df7c02555cb396ba3ea7428095c0dd68b34fce4510a1682fa2dcdc3b9214841e3addca72b141a54f95e6042093cb7d5ea183c37ce982c0ed55875f3cd6c352a3c79860d502c038e84544266b652516b293baab16cf5c71af4c096b51ba40266b5f93b1cf4cb50a922f4bf26c29cb774d06efe3257c3ba1b85356beeef079502490ded83a6283796fe35aa066896c6e61b2efe6c4113c6f14a64555a2b355dd8175eb14431ea8b4b275010f2425619b76b54b38301f05c53774be0b441746d9653c797b940979a4cdbb9b6f124bd95688e79bd6df240cc4c0c537cb085dfeabc83562acd1ea3efcfaff85a686e11868bf7570d682e878b0d63c520f1f6f1e82ada7247864a11a389d25296d45b1df35375af2026bac981fb5775a08c132c0e21275a68af5a7aaa4157607315afd21ebe693731a84599044832435df53589533f2e433c326ba2c55a2895f61fc821e53b45d347dc7566addbdbba69d63edb68ffbb99a821fe2ce7f26de09caf8f6b0cb4833f5123b329394b7f35a658a03b59af5427ee9cc82597ba2a1fc08ee5d226ff036c095e364d7e7129e1ad4ab7e4769d76e506b0cbb2870b010a245a50758304aa83400d32b46109d3361416fe575ca52f520db22280dce45dec8a81e512520c89e51fb65fbff42a149ceeb5634d04663544c2185820c702782d6352fe5693d22258886e0d819b5f86bd6355831de92a8c0904e66bcd29ff4b335d3b4f0c170ae3f46b9a8152fc04579d37e21f58d3bdb639d29c071435addc602c6f3d6a30b41cbab538cf97ab6d334181f106c663f991f533f62bf1a5922802ef0902616465e85d07e8099d1b950201c801e73aefc0f7e3bbe075cdbab69d6eace3f547d92554c11ab8020a32f36b85f42179157de80b8b1a61a862aa92aea541d16037a050392ee32c450c00e813a1baf1e1ff663206a"));
    // decode_print(Side::Server, &hex!("fdff00000eefd545b3713ec650dc4844f59652f737fa3a06d365c2a77f84da934dbf7436bfd74a72d740f43dccef8e2fa58b2ffc6bf5293fbba3485f3629bced66d2f8a20739cf01681c4ce472840faf869cdac5f7ad12bfc0b6569b5c40c23148e87af0fc241a8695e84a05104beb3d6b783d2d603e628c92552d79006bfdc4bdc3f8f20a7e3be5e290a846ccaf43c6f1191e714e605d787a2d161d9352a7155acb4e891622b8c5cf7a41a32333aa56f1579f786755dd9ed7c6f86a92bec70ed3b562dad3f602cb746e29012fee66f9b4c906aafe77c3c90dde3f1cfec236d630fa9defd0924fccdb6f98300d4bd9b66513d20c5654fc5b26e89d95d2cca7b9f7ee996587e9bbfe80b1fd2e49a59b282a5fdf94a00cc3222fe33857b79f85"));
    // decode_print(Side::Client, &hex!("ffff00000efe06d365c2a77f84da934dbf7436bfd74a72d7d545b3713ec650dc4844f59652f737fa3a004016c2cfd48685dde2ca136fbc56ceb720561b89280439c6"));
    // decode_print(Side::Client, &hex!("fdff00000efe06d365c2a77f84da934dbf7436bfd74a72d7d545b3713ec650dc4844f59652f737fa3a404d75036b0eb32dc8cd98c88c6a6a1b3b67df7aea50753993c09492423a17d2779465face7d38fdcdc338bbc3f985434c6f46b43214c7e0fd091b36c1d6d954522298541bb3772b67cdebe81b1311"));
    // decode_print(Side::Server, &hex!("fdff00000eefd545b3713ec650dc4844f59652f737fa3a06d365c2a77f84da934dbf7436bfd74a72d7401663b7f6194011fa9a85fc480e5bfb06004cf6752ba7ec"));
    // decode_print(Side::Server, &hex!("30d545b3713ec650dc4844f59652f737fa3aeea363ec2943dc6eb3f1694749b2effef6a7f4126155a0a649595ac8ece3a1aeb6fc1c573c79057100f2b8be6c00317083d95cf530796b66b499d76ae41c5c5ddb8ec5be6cace67c2c89745ad1ac50280890eaa8bcd6695b0ddf4f65341276a345f9a59296b815cf247ac5169a106a1422e88c56892e47c624a4ca33139959719079b96af6b7070a37dc1fdafc5dfeefab64cbd98996f1a9ec23ba573d0e0723243a2ace8a1d"));
    // decode_print(Side::Client, &hex!("3006d365c2a77f84da934dbf7436bfd74a72d7085e6050992f792aa95bc10f890cc8dc194fa525931ffac4"));
    // decode_print(Side::Server, &hex!("30d545b3713ec650dc4844f59652f737fa3acc1e37b7d2dac1a9fd61093c558eec69b018dde3d9db"));
    // decode_print(Side::Client, &hex!("3006d365c2a77f84da934dbf7436bfd74a72d7a40a50a7c84aaa5c6f97a9bf76063605c640a2ec6213"));

    decode_print(Side::Client, &hex!("ffff00000eff9ebe6b25b754371d0c9ecdc68c002207df074d550b28a0f77973d015482ba453f17507330044c1160e8ca52cecb1e0edf8a909cdb4a50f1f9d0d85f6b585eea286da429fefec482e58e8f0551d1479790d81800f0ee457e6e0d0efa409e608d48498afce1483ff3e899f229b0a33ae833c201379a74d3df0791b1c5fd28bffd891b2649b2fe50559dde66e25384f817a7e23d768fb4d2a8dcd0b95db9bd77019ad68febb7ed2efd9457cb0cbdb17ae5ab7dcef892743fefab778f6210623e69c0015e61093a40c320343efc9f0cd6349fb7da985169e64acae0cb9fe8d3b805171358c573562c56f0dfc43c81ac06b2520e510469f565e3acf8f628b03823d83754eae803fe0c6d68d73c3e39e8041840edeffc48af0795381cc863a1258d0cb5fcb7b3cfe7d3c732c752cfc77d6b31763b411b2e48d26b70b29b453e4b71d738a8eb781ab0268380598d5ef33a748035eee497f2e98284ed8e5a367246820b29d6d7197ecc21c31169c9a5f79ab95b845fe4166d41f5b9628574801c9917eab7b1ea2ac05d1e371db537ed3aaaac41535a05ac98a5d467ba80d928e2e0e12293aa0f5b9df5e362fc283e9a9d727035db93bebd218969f14d9495b3369fc43450f91338c3e1de8317f06f8b54cc473c5ffa7bfc0b1a069fdb64cd8b0a2b9dc760555d0e1eb338d3a1630e562be72ca941f7b7fe54bd9d2195d1dc687e2eacb48ce532855aa8e609a95d0c6f2eaad95aee3580fceed6f7383031ee68cfe1335ad319d78259bbf345af007e90282379c5507b6f530a7dd69570ada73424c9f17a0c3e6a2a8ab2ec8e99788481332d14e3bfa42b70573bd89d13e98b84a48b0acee360e55ea490bdccaa7cfe423e299960abec0e10d17e6a01d267a25b716b6a68f1cc90ef749e938d1e0a13823cafbd8a81fd5998040b84c926e0cdf5d26dff924888a81dcf5026fc526fb32d68365f5034c3bb3abc2448a72607d3e08973f4de617401dc1d2ad3d768628b541ad851fcebe1ed107dc926fbcd935bb8d5e9159251fa8c3859016d4dcfd148c11ec9199b7d3ee24c4383777e38d3ea8f4df934bdb8f2762eb38b459554632199a3f484e174ece6c6418e5b6a2ff1ce992584b60b6a0e3e4431f3a41974bcefd48635461cbb2aba2388f078ea751d24de05bea3a9479fa01bbd6dd2828a5ddc19ec77b6d5dbbba3d282978bcfc451402dc6644150bb7fcf76168c95ed744d0f0e0561007a408b0a8c08e3fc4f75b2afc3512f1d4337b5e7f6f043743e3dd43418e0c94fb90afd27e3e3c31e8471c887ffbc2a61f0d336782493d96693db45b098d97cc38a130f2aa940bc8d85b156c129dc3beb726e50ffb50c6cc28828d86375bda18477881425d1625f3dc95f0fb5c8383b29dc8c60c2e2d736bac4144046c67e7f406d0a86029d092e24c179c5bd19cccba3db8e1e8ab5b1d23b61c1719e7f8fdc42c1f4d944e76e040df84ef3fbaf89f55f541904fdb694e1870108ccdc01e2f9373c080d071d69ef099cc618ce866ccf4b82196087dbc83446db6247b8f96f7d6915af76506e0b7c39b48332d1bc5d81f2e63de79c5e46b73dbd4249c6975bc5345371396e08e6d7d0cc2937cc59760a537b04482a66c6756c860ff1ad978191ba239e2d7f1b05e4024f94b1cb43a4d88ae16652a8e6df2e68f6feffb1ddd6125b1e59de10c51a16634b042217889c10bf2c88cb88359936c1dd79d7f3b71316e64e45ce4e99b313622d7db78fa46a41c7a0ad237eaa9cdb326df"));

    // decode_print(Side::Client, &hex!("ffff00000efef2aca972962edd0f195aa1bb9a16734be91bd545b3713ec650dc4844f59652f737fa3a0044b8bbfea45ef151caaea8aed9134aa73c600b6ae087ab834698b8722666cf1bb1fc785d9fd1ad74f95f0ee146c339af282a03f95181fe520785637467a3f44c7e756c74df109204bd51a4ec596edded9aedf2d0bd3a1f83a1244faf83dbc2be1aa9f278aba4fcfb28bca83e5f34b0ad117eb062db68d0df7f80b3ffbd49970452f110a0629029d12836bf93b749d4ef3f9c178d5de4748ea5e1eb91342a41419d781d27b0a4238966d4234b503df94c3da0942c0f7add1d6c69b52829a31bc693eeeae14dd33323b573d5de3756ea2b9a3c358164db6932e0f50ec61be4f00fc01de7776260afa0ed36699ada8601a229058359b6010dcb74c2bee3ebfa41539b3285aa135c341e8755c2ab445a4d0fe5721f59068835222a93bcf3e340ca103fbc514f5ebe55381e0f4f8c45b2400d1335246960236170b5e61850e3b60cd150f205d3f264a034dd0a53eae40534ff48aee5f18fa5a3c9b49bb50913894fa15335efc6b7f50d63361c04565b2647650f3d0adc67e84a45378bb143156a2ebaa0e0f7f16fd1ccc9cc596685afce902d6c6bf6ae753863332e949c70be2e255a848bace872c2163a2890e5145d9dad6e2843b0bfad09551b5dbb259863249a1ec1aff33bb36ac9373b0506d246b69f0bc1f64340008d15263e36838b06042b36c319897265faa3b70460e5e65347f55aae04ec07a7b0e83c20bb0a466a6b46b6cbc4716f9abe3b463c5a14b7e849fa790917b9f41fcd1443b0a2dcd48e9b8f809f8d49445962b483ad198f55043d0488f16f87ce528a5305dbe97eafd525907bcd69ab3fca3b0f10b3197b257ac0c2fa423f2232ee4525fab817d42f6546b569aa4568b9ab3fd24b453963c6969b57fb265b00034b4a096530570f0d7a56e439bfa1c13db07fb3c686d753144781185418b71b9394ef9345aa42ffc6ba8633342aee2da200b61699764dae176738ebadc71ecd1ecbc6b9d8c19b272414c9a413fa18680f96713a175a2334422fe6a49865a32855caadca58272ba8eea41cc96c166f71897367079ab44994fb3ef975a1b02eb89b3c5f97dbb01820be655f8dbf062ba9e09b3c3c59e1a28e138607daf3a8ff45d60d6f878cabc8d9beead0608a019a9b4e7518e1ec873c72ffd8015c5a719299857968c06819d03168cdca67ecfe8861e68f7f846abfe5deecdda45b8d7da36def9fdf67e539d841008d8281213b605ca01fd7026f26a99497cf7dc708f4d4054c1f6de935707acb6764997f218dc372283bf56d7296f16dd8d976a648dbcc6e9457d3ad13ea04aef46ee5682352c083aabc7882406e8064949473616d13e42cea842d193d20bb2ca2af87a19586dc68a558f0d629873cec3d61970434e72e6246f197840afe324e8ce299ee8d19c7178195d5f762efdee05f4efbfe90bc48e5d8d01d0e1a62a5ec997cf056301126c65c4d1aee9f5e3f5aa529b3265f2483b8b474179f4b77db6b4b732d0c309ddc6b9d6dccac9eb3c23ed0619a5b2c04841ac033705fc3ced733e87ad7ce1eb7692a67732e893457385802f5f62f6eca60033778e35d02286b6d4b5ab579fd15a4043481981010efc3b3504344e793330aaf5f7801fb66da2346d4d2ecea2f1e8f7d93cad68d0eec4e111a2e4c4a65199826904a1da4d17dd78a4fd28d97ad29c0bfd058fb3e1207c62a9374b14a60c865940e6c00ccb6d765"));
    decode_print(Side::Server, &hex!("ffff00000eefd545b3713ec650dc4844f59652f737fa3a22df611f72be21009b880b5434e1dbaeb08d004016b5ed4f934249ed1a58d39fb56970d707e641e459a5c9"));

    /*

    //
    // client -> server 0
    //
    let client_pp_pn = hex!("00d89d6dc887026d10bbe7892567d9d0");
    let client_pp_iv = hex!("d4213359165f5e1caf724ce6");
    let client_pp_key = hex!("541b8a1e19e5db40fbfa6b345cbdfb45");

    let sample = hex!("7951caaea8aed9134aa73c600b6ae087"); // nonce 16-bytes にしてみたけど合ってるか不明。 https://github.com/quicwg/base-drafts/wiki/Test-vector-for-AES-packet-number-encryption は16バイト => 合ってた
    let mut pn = hex!("7dfea45b");
    let pn = decrypt_pp_pn(&client_pp_pn, &sample, &mut pn);
    print_hex("packet number", &pn);

    let ad = hex!("ffff00000efef2aca972962edd0f195aa1bb9a16734be91bd545b3713ec650dc4844f59652f737fa3a0044b800");
    let mut payload = hex!("fea45b7951caaea8aed9134aa73c600b6ae087ab834698b8722666cf1bb1fc785d9fd1ad74f95f0ee146c339af282a03f95181fe520785637467a3f44c7e756c74df109204bd51a4ec596edded9aedf2d0bd3a1f83a1244faf83dbc2be1aa9f278aba4fcfb28bca83e5f34b0ad117eb062db68d0df7f80b3ffbd49970452f110a0629029d12836bf93b749d4ef3f9c178d5de4748ea5e1eb91342a41419d781d27b0a4238966d4234b503df94c3da0942c0f7add1d6c69b52829a31bc693eeeae14dd33323b573d5de3756ea2b9a3c358164db6932e0f50ec61be4f00fc01de7776260afa0ed36699ada8601a229058359b6010dcb74c2bee3ebfa41539b3285aa135c341e8755c2ab445a4d0fe5721f59068835222a93bcf3e340ca103fbc514f5ebe55381e0f4f8c45b2400d1335246960236170b5e61850e3b60cd150f205d3f264a034dd0a53eae40534ff48aee5f18fa5a3c9b49bb50913894fa15335efc6b7f50d63361c04565b2647650f3d0adc67e84a45378bb143156a2ebaa0e0f7f16fd1ccc9cc596685afce902d6c6bf6ae753863332e949c70be2e255a848bace872c2163a2890e5145d9dad6e2843b0bfad09551b5dbb259863249a1ec1aff33bb36ac9373b0506d246b69f0bc1f64340008d15263e36838b06042b36c319897265faa3b70460e5e65347f55aae04ec07a7b0e83c20bb0a466a6b46b6cbc4716f9abe3b463c5a14b7e849fa790917b9f41fcd1443b0a2dcd48e9b8f809f8d49445962b483ad198f55043d0488f16f87ce528a5305dbe97eafd525907bcd69ab3fca3b0f10b3197b257ac0c2fa423f2232ee4525fab817d42f6546b569aa4568b9ab3fd24b453963c6969b57fb265b00034b4a096530570f0d7a56e439bfa1c13db07fb3c686d753144781185418b71b9394ef9345aa42ffc6ba8633342aee2da200b61699764dae176738ebadc71ecd1ecbc6b9d8c19b272414c9a413fa18680f96713a175a2334422fe6a49865a32855caadca58272ba8eea41cc96c166f71897367079ab44994fb3ef975a1b02eb89b3c5f97dbb01820be655f8dbf062ba9e09b3c3c59e1a28e138607daf3a8ff45d60d6f878cabc8d9beead0608a019a9b4e7518e1ec873c72ffd8015c5a719299857968c06819d03168cdca67ecfe8861e68f7f846abfe5deecdda45b8d7da36def9fdf67e539d841008d8281213b605ca01fd7026f26a99497cf7dc708f4d4054c1f6de935707acb6764997f218dc372283bf56d7296f16dd8d976a648dbcc6e9457d3ad13ea04aef46ee5682352c083aabc7882406e8064949473616d13e42cea842d193d20bb2ca2af87a19586dc68a558f0d629873cec3d61970434e72e6246f197840afe324e8ce299ee8d19c7178195d5f762efdee05f4efbfe90bc48e5d8d01d0e1a62a5ec997cf056301126c65c4d1aee9f5e3f5aa529b3265f2483b8b474179f4b77db6b4b732d0c309ddc6b9d6dccac9eb3c23ed0619a5b2c04841ac033705fc3ced733e87ad7ce1eb7692a67732e893457385802f5f62f6eca60033778e35d02286b6d4b5ab579fd15a4043481981010efc3b3504344e793330aaf5f7801fb66da2346d4d2ecea2f1e8f7d93cad68d0eec4e111a2e4c4a65199826904a1da4d17dd78a4fd28d97ad29c0bfd058fb3e1207c63cdd02f95ae4838e1b335fe9f0b6da31");
    let payload = decrypt_pp_payload(&client_pp_key, &client_pp_iv, &pn, &ad, &mut payload);
    print_hex("payload", &payload);


    //
    // server -> client 1
    //
    let server_pp_pn = hex!("49eb3707f0dfb919df2cafdf2c7f712f");
    let server_pp_iv = hex!("7cff52a51c5db4b7be35ff54");
    let server_pp_key = hex!("65f61c23ea93104df46e698817326abb");

    let sample = hex!("4249d9b74de91a153bb6aaf898240938");
    let mut pn = hex!("77e24ec3");
    let pn = decrypt_pp_pn(&server_pp_pn, &sample, &mut pn);
    println!("packet number: {}", hex_to_string(&pn));

    let ad = hex!("ffff00000eefd545b3713ec650dc4844f59652f737fa3a06d365c2a77f84da934dbf7436bfd74a72d700409500");
    let mut payload = hex!("e24ec34249d9b74de91a153bb6aaf898240938067b28b0c96e84afa475ffe1cb457a9700a4dc2dc36beefdbf6202b3251fadb3216e9bbe3157f55f045c59a358b8e645b3f618d85695dd3a25b7560e36b7464bb6ff1624103c94e509fae29a8c88caf11f9f905af072b759033c8bcf2411fea5dd637ae28b3725b3a9de8de5bbc1971aee03f98c629017d423603593274cd3223f");
    let payload = decrypt_pp_payload(&server_pp_key, &server_pp_iv, &pn, &ad, &mut payload);
    print_hex("payload", &payload);


    //
    // server -> client 2
    //
    let server_hs_key = hex!("e23cad831aaf559eadc0f61462fe607d13171a75908a4844a1ad45d51da98ab9");
    let server_hs_iv = hex!("7c62db0886e08b4741295942");
    let server_hs_pn = hex!("bf5279851c8961d753aaff79e64b095001e428c661019ce98beeebcb1ec7ef63");

    let client_hs_key = hex!("223eb924c5f42ed9ef2579a397d67062d1be55928c1fedd6629a9101ca75dddc");
    let client_hs_iv = hex!("97228ab773f2d8e25f0f7ddd");
    let client_hs_pn = hex!("9db32f66578541b9bcc6482aefff89fb17e660b736dbf9133e4035bb314bba86");

    // pn
    let sample = hex!("ed4150a630626d537a43b5e3a33dcdf3");
    let mut pn = hex!("f2576c0a");
    let pn = decrypt_hs_pn(&server_hs_pn, &sample, &mut pn);
    print_hex("packet number", &pn);

    // payload
    let ad = hex!("fdff00000eefd545b3713ec650dc4844f59652f737fa3a06d365c2a77f84da934dbf7436bfd74a72d743eb00");
    let mut payload = hex!("576c0aed4150a630626d537a43b5e3a33dcdf368a2ddd9c27386f571efa87c5e1f20aff1fb6f18681e52ea6ef7467974b2bb74153d41099bbe3f188cf36c79422d752f2300153be9ee1060b049f5f7b189e6074479d9bdf2d0ba9fb29c3f4a07e52d2089e098ec607b8ed433fe742b73dec8baeed048b251d02bd00d38a609897d0d02733b5fd6ebcfac3e7398a84bf824c96caa9ba370407969a2bbd457d470ff9eecd9391af412482fbaf100d3645129fbbf507c5068651e18d8e5f7a5198604af9e6eea3adfca8d2930b30e4cb59e7fa0233018edba7d582627bcaa62f2b3b1e745d873fbc46c79157f6b9a569ffe476dffd2f53244594e6bcc148705cf4d9a4f03b4fb04a9f41bcce4f8992a229bd32f710184cb995942775f56942243678b81c437dfe2a86d748a853261ad00698028f4607d50329d1383df1508c1f9f34cad92756a540e5c38df7c02555cb396ba3ea7428095c0dd68b34fce4510a1682fa2dcdc3b9214841e3addca72b141a54f95e6042093cb7d5ea183c37ce982c0ed55875f3cd6c352a3c79860d502c038e84544266b652516b293baab16cf5c71af4c096b51ba40266b5f93b1cf4cb50a922f4bf26c29cb774d06efe3257c3ba1b85356beeef079502490ded83a6283796fe35aa066896c6e61b2efe6c4113c6f14a64555a2b355dd8175eb14431ea8b4b275010f2425619b76b54b38301f05c53774be0b441746d9653c797b940979a4cdbb9b6f124bd95688e79bd6df240cc4c0c537cb085dfeabc83562acd1ea3efcfaff85a686e11868bf7570d682e878b0d63c520f1f6f1e82ada7247864a11a389d25296d45b1df35375af2026bac981fb5775a08c132c0e21275a68af5a7aaa4157607315afd21ebe693731a84599044832435df53589533f2e433c326ba2c55a2895f61fc821e53b45d347dc7566addbdbba69d63edb68ffbb99a821fe2ce7f26de09caf8f6b0cb4833f5123b329394b7f35a658a03b59af5427ee9cc82597ba2a1fc08ee5d226ff036c095e364d7e7129e1ad4ab7e4769d76e506b0cbb2870b010a245a50758304aa83400d32b46109d3361416fe575ca52f520db22280dce45dec8a81e512520c89e51fb65fbff42a149ceeb5634d04663544c2185820c702782d6352fe5693d22258886e0d819b5f86bd6355831de92a8c0904e66bcd29ff4b335d3b4f0c170ae3f46b9a8152fc04579d37e21f58d3bdb639d29c071435addc602c6f3d6a30b41cbab538cf97ab6d334181f106c663f991f533f62bf1a5922802ef0902616465e85d07e8099d1b950201c801e73aefc0f7e3bbe075cdbab69d6eace3f547d92554c11ab8020a32f36b85f42179157de80b8b1a61a862aa92aea541d16037a050392ee32c450c00e813a1baf1e1ff663206a");
    let payload = decrypt_hs_payload(&server_hs_key, &server_hs_iv, &pn, &ad, &mut payload);
    print_hex("payload", &payload);


    //
    // server -> client 3
    //
    let sample = hex!("2fa58b2ffc6bf5293fbba3485f3629bc");
    let mut pn = hex!("3dccef8e");
    let pn = decrypt_hs_pn(&server_hs_pn, &sample, &mut pn);
    print_hex("packet number", &pn);

    let ad = hex!("fdff00000eefd545b3713ec650dc4844f59652f737fa3a06d365c2a77f84da934dbf7436bfd74a72d740f401");
    let mut payload = hex!("ccef8e2fa58b2ffc6bf5293fbba3485f3629bced66d2f8a20739cf01681c4ce472840faf869cdac5f7ad12bfc0b6569b5c40c23148e87af0fc241a8695e84a05104beb3d6b783d2d603e628c92552d79006bfdc4bdc3f8f20a7e3be5e290a846ccaf43c6f1191e714e605d787a2d161d9352a7155acb4e891622b8c5cf7a41a32333aa56f1579f786755dd9ed7c6f86a92bec70ed3b562dad3f602cb746e29012fee66f9b4c906aafe77c3c90dde3f1cfec236d630fa9defd0924fccdb6f98300d4bd9b66513d20c5654fc5b26e89d95d2cca7b9f7ee996587e9bbfe80b1fd2e49a59b282a5fdf94a00cc3222fe33857b79f85");
    let payload = decrypt_hs_payload(&server_hs_key, &server_hs_iv, &pn, &ad, &mut payload);
    print_hex("payload", &payload);

    //
    // client -> server 2
    //
    let sample = hex!("85dde2ca136fbc56ceb720561b892804");
    let mut pn = hex!("c2cfd486");
    let pn = decrypt_pp_pn(&client_pp_pn, &sample, &mut pn); // dcid 変わったけど、initial のシークレットは最初に送った dcid なのでこの鍵で大丈夫
    print_hex("packet number", &pn);

    let ad = hex!("ffff00000efe06d365c2a77f84da934dbf7436bfd74a72d7d545b3713ec650dc4844f59652f737fa3a00401601");
    let mut payload = hex!("cfd48685dde2ca136fbc56ceb720561b89280439c6");
    let payload = decrypt_pp_payload(&client_pp_key, &client_pp_iv, &pn, &ad, &mut payload);
    print_hex("payload", &payload);

    //
    // client -> server 3
    //
    let sample = hex!("b32dc8cd98c88c6a6a1b3b67df7aea50");
    let mut pn = hex!("75036b0e");
    let pn = decrypt_hs_pn(&client_hs_pn, &sample, &mut pn);
    print_hex("packet number", &pn);

    let ad = hex!("fdff00000efe06d365c2a77f84da934dbf7436bfd74a72d7d545b3713ec650dc4844f59652f737fa3a404d00");
    let mut payload = hex!("036b0eb32dc8cd98c88c6a6a1b3b67df7aea50753993c09492423a17d2779465face7d38fdcdc338bbc3f985434c6f46b43214c7e0fd091b36c1d6d954522298541bb3772b67cdebe81b1311");
    let payload = decrypt_hs_payload(&client_hs_key, &client_hs_iv, &pn, &ad, &mut payload);
    print_hex("payload", &payload);

    */
}
