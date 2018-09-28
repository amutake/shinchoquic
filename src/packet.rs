use byteorder::{ByteOrder, NetworkEndian};
use rust_crypto::aead::AeadEncryptor;
use rust_crypto::aes::{ctr as aes_ctr, KeySize};
use rust_crypto::aes_gcm::AesGcm;
use std::iter::repeat;

use crypto::{PhaseKeys, AUTH_TAG_LEN, PN_SAMPLE_LEN};
use error::{Error, Result};
use util::{left_pad, xor};

#[derive(Debug, Clone)]
pub struct ConnectionId(Vec<u8>);

impl ConnectionId {
	pub fn new(id: Vec<u8>) -> Self {
		ConnectionId(id)
	}

	pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
		let len = self.0.len();
		buf[..len].copy_from_slice(&self.0);
		Ok(len)
	}

	// Connection Id Length (for DCIL and SCIL)
	pub fn cil(&self) -> u8 {
		if self.0.len() == 0 {
			0
		} else {
			self.0.len() as u8 - 3
		}
	}

	pub fn inner(&self) -> &Vec<u8> {
		&self.0
	}
}

#[derive(Debug, Clone, Default)]
pub struct PacketNumber(u64);
impl PacketNumber {
	fn new(n: u64) -> Self {
		PacketNumber(n)
	}

	// TODO: 大きいパケット番号の対応
	fn encode(&self, buf: &mut [u8]) -> Result<usize> {
		buf[0] = self.0 as u8;
		Ok(1)
	}

	// TODO: 大きいパケット番号の対応
	fn size(&self) -> usize {
		1
	}
}

#[derive(Debug, Default)]
pub struct PacketNumberSpaces {
	initial: u64,
	handshake: u64,
	application: u64,
}

impl PacketNumberSpaces {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn next_initial(&mut self) -> PacketNumber {
		let n = self.initial;
		self.initial = n + 1;
		PacketNumber::new(n)
	}
}

#[derive(Debug, Clone)]
pub enum Frame {
	Crypto { offset: u64, payload: Vec<u8> },
	Padding,
}

impl Frame {
	pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
		let mut offset = 0;
		offset += self.encode_type(buf)?;
		match self {
			Frame::Crypto {
				offset: crypto_offset,
				payload,
			} => {
				offset += VariableLengthInteger::new(*crypto_offset).encode(&mut buf[offset..])?;
				let payload_len = payload.len();
				offset += VariableLengthInteger::new(payload_len as u64).encode(&mut buf[offset..])?;
				buf[offset..offset + payload_len].copy_from_slice(&payload[..]);
				offset += payload_len;
				Ok(offset)
			}
			Frame::Padding => Ok(offset),
		}
	}

	pub fn encode_type(&self, buf: &mut [u8]) -> Result<usize> {
		match self {
			Frame::Crypto { .. } => {
				buf[0] = 0x18;
				Ok(1)
			}
			Frame::Padding => {
				buf[0] = 0x00;
				Ok(1)
			}
		}
	}

	pub fn size(&self) -> usize {
		match self {
			Frame::Crypto { offset, payload } => {
				1 + VariableLengthInteger::new(*offset).size()
					+ VariableLengthInteger::new(payload.len() as u64).size()
					+ payload.len()
			}
			Frame::Padding => 1,
		}
	}
}

pub type Version = u32;

#[derive(Debug, Clone)]
pub struct Payload(pub Vec<Frame>);
impl Payload {
	pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
		let mut offset = 0;
		for f in self.0.iter() {
			offset += f.encode(&mut buf[offset..])?;
		}
		Ok(offset)
	}

	pub fn encode_with_padding(&self, buf: &mut [u8]) -> Result<usize> {
		let mut offset = self.encode(buf)?;
		while offset < 1200 {
			buf[offset] = 0;
			offset += 1;
		}
		Ok(offset)
	}

	fn size(&self) -> usize {
		self.0.iter().map(|f| f.size()).sum()
	}

	fn size_with_padding(&self) -> usize {
		self.size().max(1200)
	}
}

#[derive(Debug, Clone)]
pub enum Packet {
	Initial {
		version: Version,
		dst_conn_id: ConnectionId,
		src_conn_id: ConnectionId,
		token: Vec<u8>,
		packet_number: PacketNumber,
		payload: Payload,
	},
}
impl Packet {
	// 暗号化もやっちゃう
	pub fn encode(&self, keys: &PhaseKeys, buf: &mut [u8]) -> Result<usize> {
		match self {
			Packet::Initial {
				version,
				dst_conn_id,
				src_conn_id,
				token,
				packet_number,
				payload,
			} => {
				let keys = keys.clone().initial.ok_or(Error::NoKeyError)?;
				let mut offset = 0;
				// Packet Type
				buf[0] = 0xff; // long header & initial packet
				offset += 1;
				// Version
				NetworkEndian::write_u32(&mut buf[offset..], *version);
				offset += 4;
				// DCIL & SCIL
				buf[offset] = (dst_conn_id.cil() << 4) + src_conn_id.cil();
				offset += 1;
				// Destination Connection ID
				offset += dst_conn_id.encode(&mut buf[offset..])?;
				// Source Connection ID
				offset += src_conn_id.encode(&mut buf[offset..])?;
				// Token Length
				let token_len = token.len();
				offset += VariableLengthInteger::new(token_len as u64).encode(&mut buf[offset..])?;
				// Token
				buf[offset..offset + token_len].copy_from_slice(&token);
				offset += token_len;
				// Length
				let rest_len = packet_number.size() + payload.size_with_padding() + AUTH_TAG_LEN;
				offset += VariableLengthInteger::new(rest_len as u64).encode(&mut buf[offset..])?;
				// Packet Number (not encrypted)
				let pn_size = packet_number.encode(&mut buf[offset..])?;
				// Payload (not encrypted)
				let payload_size = payload.encode_with_padding(&mut buf[offset + pn_size..])?;
				// Payload Encryption
				{
					let aad = buf[..offset + pn_size].to_vec();
					let nonce = xor(
						&keys.write_iv,
						&left_pad(&buf[offset..offset + pn_size], keys.write_iv.len()),
					);
					let mut cipher = AesGcm::new(KeySize::KeySize128, &keys.write_key, &nonce, &aad);
					let mut payload = buf[offset + pn_size..offset + pn_size + payload_size].to_vec();
					let (ciphertext, tag) = buf.split_at_mut(offset + pn_size + payload_size);
					cipher.encrypt(
						&payload,
						&mut ciphertext[offset + pn_size..offset + pn_size + payload_size],
						tag,
					);
				}
				// Packet Number Encryption
				let sample = buf[offset + 4..offset + 4 + PN_SAMPLE_LEN].to_vec();
				let mut cipher = aes_ctr(KeySize::KeySize128, &keys.write_pn, &sample);
				let mut pn = buf[offset..offset + pn_size].to_vec();
				cipher.process(&pn, &mut buf[offset..offset + pn_size]);

				offset += rest_len;
				//
				Ok(offset)
			}
		}
	}

	pub fn decode(data: &[u8]) -> Self {
		unimplemented!();
	}
}

struct VariableLengthInteger(u64);
impl VariableLengthInteger {
	pub fn new(n: u64) -> Self {
		VariableLengthInteger(n)
	}

	pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
		// なぜ buf: &mut [u8] を取るか？
		// なぜ Vec<u8> を返さないか？
		// => byteorder が Read/Write のインタフェースっぽくなっている
		// Vec だと、一旦中で mut slice を作って、書き込んで、vec に変換して、サイズを調整して、返す
		// それなら buf もらって、書き込んで、サイズを返したほうがコード量少なくなる
		if self.0 >> 6 == 0 {
			buf[0] = self.0 as u8;
			Ok(1)
		} else if self.0 >> 14 == 0 {
			NetworkEndian::write_u16(buf, (1u16 << 14) ^ (self.0 as u16));
			Ok(2)
		} else if self.0 >> 30 == 0 {
			NetworkEndian::write_u32(buf, (2u32 << 30) ^ (self.0 as u32));
			Ok(4)
		} else if self.0 >> 62 == 0 {
			NetworkEndian::write_u64(buf, (3u64 << 62) ^ self.0);
			Ok(8)
		} else {
			Err(Error::EncodeError)
		}
	}

	fn size(&self) -> usize {
		if self.0 >> 6 == 0 {
			1
		} else if self.0 >> 14 == 0 {
			2
		} else if self.0 >> 30 == 0 {
			4
		} else if self.0 >> 62 == 0 {
			8
		} else {
			panic!("too large")
		}
	}
}
