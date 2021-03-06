use byteorder::{ByteOrder, NetworkEndian};
use rand::{thread_rng, Rng};
use rust_crypto::aead::{AeadDecryptor, AeadEncryptor};
use rust_crypto::aes::{ctr as aes_ctr, KeySize};
use rust_crypto::aes_gcm::AesGcm;

use crypto::{PhaseKeys, AUTH_TAG_LEN, PN_SAMPLE_LEN};
use error::{Error, Result};
use util::{left_pad, xor};

#[derive(Debug, Clone)]
pub struct ConnectionId(Vec<u8>);
const CONN_ID_LEN: usize = 18;
impl ConnectionId {
	pub fn random() -> Self {
		let mut id = [0; CONN_ID_LEN];
		thread_rng().fill(&mut id);
		ConnectionId(id.to_vec())
	}

	pub fn decode(buf: &[u8]) -> Result<Self> {
		Ok(ConnectionId(buf.to_vec()))
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketNumber(u64);
impl PacketNumber {
	fn new(n: u64) -> Self {
		PacketNumber(n)
	}

	// TODO: 大きいパケット番号の対応
	// ここには復号済みのバッファがやってくる想定
	fn decode(buf: &[u8]) -> Result<(Self, usize)> {
		Ok((PacketNumber(buf[0] as u64), 1))
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
		self.initial += 1;
		PacketNumber::new(n)
	}

	pub fn next_handshake(&mut self) -> PacketNumber {
		let n = self.handshake;
		self.handshake += 1;
		PacketNumber::new(n)
	}

	pub fn next_application(&mut self) -> PacketNumber {
		let n = self.application;
		self.application += 1;
		PacketNumber::new(n)
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckBlocks {
	pub first: u64,
	pub additional: Vec<(u64, u64)>, // (gap, ack block)
}

impl AckBlocks {
	fn decode(buf: &[u8]) -> Result<(Self, usize)> {
		let mut offset = 0;
		let (count, amt) = VariableLengthInteger::decode(&buf[offset..])?;
		offset += amt;
		let (first, amt) = VariableLengthInteger::decode(&buf[offset..])?;
		offset += amt;
		let mut additional = Vec::with_capacity(count as usize);
		for _ in 0..count {
			let (gap, amt) = VariableLengthInteger::decode(&buf[offset..])?;
			offset += amt;
			let (block, amt) = VariableLengthInteger::decode(&buf[offset..])?;
			offset += amt;
			additional.push((gap, block));
		}
		Ok((AckBlocks { first, additional }, offset))
	}

	fn encode(&self, buf: &mut [u8]) -> Result<usize> {
		let mut offset = 0;
		offset +=
			VariableLengthInteger::new(self.additional.len() as u64).encode(&mut buf[offset..])?;
		offset += VariableLengthInteger::new(self.first).encode(&mut buf[offset..])?;
		for (gap, block) in self.additional.iter() {
			offset += VariableLengthInteger::new(*gap).encode(&mut buf[offset..])?;
			offset += VariableLengthInteger::new(*block).encode(&mut buf[offset..])?;
		}
		Ok(offset)
	}

	fn size(&self) -> usize {
		let additional_size: usize = self
			.additional
			.iter()
			.map(|(gap, block)| {
				VariableLengthInteger::new(*gap).size() + VariableLengthInteger::new(*block).size()
			}).sum();
		VariableLengthInteger::new(self.additional.len() as u64).size()
			+ VariableLengthInteger::new(self.first).size()
			+ additional_size
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
	Crypto {
		offset: u64,
		data: Vec<u8>,
	},
	ConnectionClose {
		error_code: u16, // TODO: enum
		frame_type: u64, // ?
		reason: Vec<u8>,
	},
	Ack {
		largest: u64,
		delay: u64,
		blocks: AckBlocks,
	},
	Padding,
	Stream {
		id: u64,
		fin: bool,
		offset: Option<u64>,
		data: Vec<u8>,
	},
}

impl Frame {
	fn decode(buf: &[u8]) -> Result<(Self, usize)> {
		let mut offset = 1; // consume first byte
		match buf[0] {
			0x00 => Ok((Frame::Padding, offset)),
			0x02 => {
				let error_code = NetworkEndian::read_u16(&buf[offset..offset + 2]);
				offset += 2;
				let (frame_type, amt) = VariableLengthInteger::decode(&buf[offset..])?;
				offset += amt;
				let (reason_len, amt) = VariableLengthInteger::decode(&buf[offset..])?;
				offset += amt;
				let reason = buf[offset..offset + reason_len as usize].to_vec();
				offset += reason_len as usize;
				Ok((
					Frame::ConnectionClose {
						error_code,
						frame_type,
						reason,
					},
					offset,
				))
			}
			0x0d => {
				let (largest, amt) = VariableLengthInteger::decode(&buf[offset..])?;
				offset += amt;
				let (delay, amt) = VariableLengthInteger::decode(&buf[offset..])?;
				offset += amt;
				let (blocks, amt) = AckBlocks::decode(&buf[offset..])?;
				offset += amt;
				Ok((
					Frame::Ack {
						largest,
						delay,
						blocks,
					},
					offset,
				))
			}
			0x10...0x17 => {
				let off_bit = (buf[0] & 0b0000_0100) >> 2;
				let len_bit = (buf[0] & 0b0000_0010) >> 1;
				let fin = (buf[0] & 0b0000_0001) == 1;
				let (id, amt) = VariableLengthInteger::decode(&buf[offset..])?;
				offset += amt;
				let stream_offset = if off_bit == 1 {
					let (n, amt) = VariableLengthInteger::decode(&buf[offset..])?;
					offset += amt;
					Some(n)
				} else {
					None
				};
				let length = if len_bit == 1 {
					let (n, amt) = VariableLengthInteger::decode(&buf[offset..])?;
					offset += amt;
					n
				} else {
					buf[offset..].len() as u64
				};
				let data = buf[offset..offset + length as usize].to_vec();
				Ok((
					Frame::Stream {
						id,
						fin,
						offset: stream_offset,
						data,
					},
					offset + length as usize,
				))
			}
			0x18 => {
				let (crypto_offset, amt) = VariableLengthInteger::decode(&buf[offset..])?;
				offset += amt;
				let (data_len, amt) = VariableLengthInteger::decode(&buf[offset..])?;
				offset += amt;
				let data = buf[offset..offset + data_len as usize].to_vec();
				offset += data_len as usize;
				Ok((
					Frame::Crypto {
						offset: crypto_offset,
						data,
					},
					offset,
				))
			}
			_ => Err(Error::DecodeError),
		}
	}

	fn encode(&self, buf: &mut [u8]) -> Result<usize> {
		let mut offset = 0;
		offset += self.encode_type(buf)?;
		match self {
			Frame::Padding => Ok(offset),
			Frame::ConnectionClose {
				error_code,
				frame_type,
				reason,
			} => {
				NetworkEndian::write_u16(&mut buf[offset..offset + 2], *error_code);
				offset += 2;
				offset += VariableLengthInteger::new(*frame_type).encode(&mut buf[offset..])?;
				let reason_len = reason.len();
				offset += VariableLengthInteger::new(reason_len as u64).encode(&mut buf[offset..])?;
				buf[offset..offset + reason_len].copy_from_slice(&reason[..]);
				offset += reason_len;
				Ok(offset)
			}
			Frame::Ack {
				largest,
				delay,
				blocks,
			} => {
				offset += VariableLengthInteger::new(*largest).encode(&mut buf[offset..])?;
				offset += VariableLengthInteger::new(*delay).encode(&mut buf[offset..])?;
				offset += blocks.encode(&mut buf[offset..])?;
				Ok(offset)
			}
			Frame::Stream {
				id,
				offset: stream_offset,
				data,
				..
			} => {
				// 最後のフレームかどうかわからないので、とりあえず length をいれておく (TODO)
				// See also: encode_type
				offset += VariableLengthInteger::new(*id).encode(&mut buf[offset..])?;
				offset += stream_offset.map_or(Ok(0), |o| {
					VariableLengthInteger::new(o).encode(&mut buf[offset..])
				})?;
				let data_len = data.len();
				offset += VariableLengthInteger::new(data_len as u64).encode(&mut buf[offset..])?;
				buf[offset..offset + data_len].copy_from_slice(&data[..]);
				offset += data_len;
				Ok(offset)
			}
			Frame::Crypto {
				offset: crypto_offset,
				data,
			} => {
				offset += VariableLengthInteger::new(*crypto_offset).encode(&mut buf[offset..])?;
				let data_len = data.len();
				offset += VariableLengthInteger::new(data_len as u64).encode(&mut buf[offset..])?;
				buf[offset..offset + data_len].copy_from_slice(&data[..]);
				offset += data_len;
				Ok(offset)
			}
		}
	}

	pub fn encode_type(&self, buf: &mut [u8]) -> Result<usize> {
		match self {
			Frame::Padding => {
				buf[0] = 0x00;
				Ok(1)
			}
			Frame::ConnectionClose { .. } => {
				buf[0] = 0x02;
				Ok(1)
			}
			Frame::Ack { .. } => {
				buf[0] = 0x0d;
				Ok(1)
			}
			Frame::Stream { offset, fin, .. } => {
				// 最後のフレームかどうかわからないので、とりあえず LEN bit を立てておく (TODO)
				// See also: encode
				let n = 0b0001_0000
					^ offset.map_or(0b0000_0000, |_| 0b0000_0100)
					^ 0b0000_0010 // <- LEN bit
					^ if *fin { 0b0000_0001 } else { 0b0000_0000 };
				buf[0] = n;
				Ok(1)
			}
			Frame::Crypto { .. } => {
				buf[0] = 0x18;
				Ok(1)
			}
		}
	}

	pub fn size(&self) -> usize {
		match self {
			Frame::Padding => 1,
			Frame::ConnectionClose {
				frame_type, reason, ..
			} => {
				1 + 2
					+ VariableLengthInteger::new(*frame_type).size()
					+ VariableLengthInteger::new(reason.len() as u64).size()
					+ reason.len()
			}
			Frame::Ack {
				largest,
				delay,
				blocks,
			} => {
				1 + VariableLengthInteger::new(*largest).size()
					+ VariableLengthInteger::new(*delay).size()
					+ blocks.size()
			}
			Frame::Stream {
				id, offset, data, ..
			} => {
				1 + VariableLengthInteger::new(*id).size()
					+ offset.map_or(0, |o| VariableLengthInteger::new(o).size())
					+ VariableLengthInteger::new(data.len() as u64).size()
					+ data.len()
			}
			Frame::Crypto { offset, data } => {
				1 + VariableLengthInteger::new(*offset).size()
					+ VariableLengthInteger::new(data.len() as u64).size()
					+ data.len()
			}
		}
	}
}

pub type Version = u32;

#[derive(Debug, Clone)]
pub struct Payload {
	pub frames: Vec<Frame>,
}
impl Payload {
	// ペイロードサイズぴったりのバッファが入力として与えられることを想定
	fn decode(buf: &[u8]) -> Result<Self> {
		let len = buf.len();
		let mut offset = 0;
		let mut frames = vec![];
		while offset != len {
			let (frame, amt) = Frame::decode(&buf[offset..])?;
			// PADDING フレームは取り除く
			// しなくてもいいかも
			if frame != Frame::Padding {
				frames.push(frame);
			}
			offset += amt;
		}
		Ok(Payload { frames })
	}

	pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
		let mut offset = 0;
		for f in self.frames.iter() {
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
		self.frames.iter().map(|f| f.size()).sum()
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
	Handshake {
		version: Version,
		dst_conn_id: ConnectionId,
		src_conn_id: ConnectionId,
		packet_number: PacketNumber,
		payload: Payload,
	},
	Short {
		dst_conn_id: ConnectionId,
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
				let keys = keys.initial.as_ref().ok_or(Error::NoKeyError)?;
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
				let rest_len = if packet_number == &PacketNumber(0) {
					packet_number.size() + payload.size_with_padding() + AUTH_TAG_LEN
				} else {
					packet_number.size() + payload.size() + AUTH_TAG_LEN
				};
				offset += VariableLengthInteger::new(rest_len as u64).encode(&mut buf[offset..])?;
				// Packet Number (not encrypted)
				let pn_size = packet_number.encode(&mut buf[offset..])?;
				// Payload (not encrypted)
				let payload_size = if packet_number == &PacketNumber(0) {
					payload.encode_with_padding(&mut buf[offset + pn_size..])?
				} else {
					payload.encode(&mut buf[offset + pn_size..])?
				};
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
			Packet::Handshake {
				version,
				dst_conn_id,
				src_conn_id,
				packet_number,
				payload,
			} => {
				let keys = keys.handshake.as_ref().ok_or(Error::NoKeyError)?;
				let mut offset = 0;
				// Packet Type
				buf[0] = 0xfd; // long header & handshake packet
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
				// Length
				let rest_len = packet_number.size() + payload.size() + AUTH_TAG_LEN;
				offset += VariableLengthInteger::new(rest_len as u64).encode(&mut buf[offset..])?;
				// Packet Number (not encrypted)
				let pn_size = packet_number.encode(&mut buf[offset..])?;
				// Payload (not encrypted)
				let payload_size = payload.encode(&mut buf[offset + pn_size..])?;
				// Payload Encryption
				{
					let aad = buf[..offset + pn_size].to_vec();
					let nonce = xor(
						&keys.write_iv,
						&left_pad(&buf[offset..offset + pn_size], keys.write_iv.len()),
					);

					let mut cipher = AesGcm::new(KeySize::KeySize128, &keys.write_key, &nonce, &aad); // TODO: use negotiated ciphersuite
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
				let mut cipher = aes_ctr(KeySize::KeySize128, &keys.write_pn, &sample); // TODO: use negotiated ciphersuite
				let mut pn = buf[offset..offset + pn_size].to_vec();
				cipher.process(&pn, &mut buf[offset..offset + pn_size]);

				offset += rest_len;
				//
				Ok(offset)
			}
			Packet::Short {
				dst_conn_id,
				packet_number,
				payload,
			} => {
				let keys = keys.one_rtt.as_ref().ok_or(Error::NoKeyError)?;
				let mut offset = 0;
				// Flags
				buf[0] = 0b0011_0000; // TODO: key phase bit
				offset += 1;
				// Destination Connection ID
				offset += dst_conn_id.encode(&mut buf[offset..])?;
				// Packet Number (not encrypted)
				let pn_size = packet_number.encode(&mut buf[offset..])?;
				// Payload (not encrypted)
				let payload_size = payload.encode(&mut buf[offset + pn_size..])?;
				// Payload Encryption
				{
					let aad = buf[..offset + pn_size].to_vec();
					let nonce = xor(
						&keys.write_iv,
						&left_pad(&buf[offset..offset + pn_size], keys.write_iv.len()),
					);

					let mut cipher = AesGcm::new(KeySize::KeySize128, &keys.write_key, &nonce, &aad); // TODO: use negotiated ciphersuite
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
				let mut cipher = aes_ctr(KeySize::KeySize128, &keys.write_pn, &sample); // TODO: use negotiated ciphersuite
				let mut pn = buf[offset..offset + pn_size].to_vec();
				cipher.process(&pn, &mut buf[offset..offset + pn_size]);
				//
				Ok(offset + pn_size + payload_size + AUTH_TAG_LEN)
			}
		}
	}

	pub fn decode(buf: &[u8], keys: &PhaseKeys) -> Result<(Self, usize)> {
		let mut offset = 0;
		if buf[0] >> 7 == 1 {
			// Long Header
			if buf[0] & 0b0111_1111 == 0x7f {
				// Initial
				offset += 1;
				let keys = keys.initial.as_ref().ok_or(Error::NoKeyError)?;
				// Version
				let version = NetworkEndian::read_u32(&buf[offset..offset + 4]);
				offset += 4;
				// DCIL & SCIL
				let mut scil = (buf[offset] >> 4) as usize;
				if scil > 0 {
					scil += 3
				};
				let mut dcil = (buf[offset] & 0b0000_1111) as usize;
				if dcil > 0 {
					dcil += 3
				};
				offset += 1;
				// Destination Connection ID
				let dst_conn_id = ConnectionId::decode(&buf[offset..offset + dcil])?;
				offset += dcil;
				// Source Connection ID
				let src_conn_id = ConnectionId::decode(&buf[offset..offset + scil])?;
				offset += scil;
				// Token Length
				let (token_len, amt) = VariableLengthInteger::decode(&buf[offset..])?;
				offset += amt;
				// Token
				let token = buf[offset..offset + token_len as usize].to_vec();
				offset += token_len as usize;
				// Length
				let (length, amt) = VariableLengthInteger::decode(&buf[offset..])?;
				offset += amt;
				// Packet Number
				// 一旦4バイトで取得
				let pn_offset = offset;
				let mut pn = [0; 4];
				let sample = &buf[offset + 4..offset + 4 + PN_SAMPLE_LEN];
				let mut cipher = aes_ctr(KeySize::KeySize128, &keys.read_pn, &sample);
				cipher.process(&buf[offset..offset + 4], &mut pn);
				// 復号した4バイトから本当の桁数を取る
				let (packet_number, amt) = PacketNumber::decode(&pn)?;
				offset += amt;
				// Payload
				// 一旦もとのパケット番号まで読み込んでから、復号済みパケット番号に差し替える
				let mut aad = buf[..offset].to_vec();
				packet_number.encode(&mut aad[pn_offset..])?;
				let nonce = xor(
					&keys.read_iv,
					&left_pad(&aad[pn_offset..], keys.read_iv.len()),
				);
				let mut cipher = AesGcm::new(KeySize::KeySize128, &keys.read_key, &nonce, &aad);
				let mut payload = vec![0; pn_offset + length as usize - AUTH_TAG_LEN - offset];
				let success = cipher.decrypt(
					&buf[offset..pn_offset + length as usize - AUTH_TAG_LEN],
					&mut payload,
					&buf[pn_offset + length as usize - AUTH_TAG_LEN..pn_offset + length as usize],
				);
				if !success {
					return Err(Error::DecryptError);
				}
				let payload = Payload::decode(&payload)?;
				offset = pn_offset + length as usize;

				Ok((
					Packet::Initial {
						version,
						dst_conn_id,
						src_conn_id,
						token,
						packet_number,
						payload,
					},
					offset,
				))
			} else if buf[0] & 0b0111_1111 == 0x7d {
				// Handshake
				offset += 1;
				let keys = keys.handshake.as_ref().ok_or(Error::NoKeyError)?;
				// Version
				let version = NetworkEndian::read_u32(&buf[offset..offset + 4]);
				offset += 4;
				// DCIL & SCIL
				let mut scil = (buf[offset] >> 4) as usize;
				if scil > 0 {
					scil += 3
				};
				let mut dcil = (buf[offset] & 0b0000_1111) as usize;
				if dcil > 0 {
					dcil += 3
				};
				offset += 1;
				// Destination Connection ID
				let dst_conn_id = ConnectionId::decode(&buf[offset..offset + dcil])?;
				offset += dcil;
				// Source Connection ID
				let src_conn_id = ConnectionId::decode(&buf[offset..offset + scil])?;
				offset += scil;
				// Length
				let (length, amt) = VariableLengthInteger::decode(&buf[offset..])?;
				offset += amt;
				// Packet Number
				// 一旦4バイトで取得
				let pn_offset = offset;
				let mut pn = [0; 4];
				let sample = &buf[offset + 4..offset + 4 + PN_SAMPLE_LEN];
				let mut cipher = aes_ctr(KeySize::KeySize128, &keys.read_pn, &sample);
				cipher.process(&buf[offset..offset + 4], &mut pn);
				// 復号した4バイトから本当の桁数を取る
				let (packet_number, amt) = PacketNumber::decode(&pn)?;
				offset += amt;
				// Payload
				// 一旦もとのパケット番号まで読み込んでから、復号済みパケット番号に差し替える
				let mut aad = buf[..offset].to_vec();
				packet_number.encode(&mut aad[pn_offset..])?;
				let nonce = xor(
					&keys.read_iv,
					&left_pad(&aad[pn_offset..], keys.read_iv.len()),
				);
				let mut cipher = AesGcm::new(KeySize::KeySize128, &keys.read_key, &nonce, &aad);
				let mut payload = vec![0; pn_offset + length as usize - AUTH_TAG_LEN - offset];
				let success = cipher.decrypt(
					&buf[offset..pn_offset + length as usize - AUTH_TAG_LEN],
					&mut payload,
					&buf[pn_offset + length as usize - AUTH_TAG_LEN..pn_offset + length as usize],
				);
				if !success {
					return Err(Error::DecryptError);
				}
				let payload = Payload::decode(&payload)?;
				offset = pn_offset + length as usize;

				Ok((
					Packet::Handshake {
						version,
						dst_conn_id,
						src_conn_id,
						packet_number,
						payload,
					},
					offset,
				))
			} else {
				Err(Error::NotSupportedError)
			}
		} else {
			// 1RTT (入力全体が1つのパケットと扱う)
			let keys = keys.one_rtt.as_ref().ok_or(Error::NoKeyError)?;
			// Flags
			// ...omit
			offset += 1;
			// Destination Connection ID
			let dst_conn_id = ConnectionId::decode(&buf[offset..offset + CONN_ID_LEN])?;
			offset += CONN_ID_LEN;
			// Packet Number
			// 一旦4バイトで取得
			let pn_offset = offset;
			let mut pn = [0; 4];
			let sample = &buf[offset + 4..offset + 4 + PN_SAMPLE_LEN];
			let mut cipher = aes_ctr(KeySize::KeySize128, &keys.read_pn, &sample);
			cipher.process(&buf[offset..offset + 4], &mut pn);
			// 復号した4バイトから本当の桁数を取る
			let (packet_number, amt) = PacketNumber::decode(&pn)?;
			offset += amt;
			// Payload
			// 一旦もとのパケット番号まで読み込んでから、復号済みパケット番号に差し替える
			let mut aad = buf[..offset].to_vec();
			packet_number.encode(&mut aad[pn_offset..])?;
			let nonce = xor(
				&keys.read_iv,
				&left_pad(&aad[pn_offset..], keys.read_iv.len()),
			);
			let packet_len = buf.len();
			let mut cipher = AesGcm::new(KeySize::KeySize128, &keys.read_key, &nonce, &aad);
			let mut payload = vec![0; packet_len - AUTH_TAG_LEN - offset];
			let success = cipher.decrypt(
				&buf[offset..packet_len - AUTH_TAG_LEN],
				&mut payload,
				&buf[packet_len - AUTH_TAG_LEN..],
			);
			if !success {
				return Err(Error::DecryptError);
			}
			use util;
			util::print_hex("payload", &payload);
			let payload = Payload::decode(&payload)?;

			Ok((
				Packet::Short {
					dst_conn_id,
					packet_number,
					payload,
				},
				packet_len,
			))
		}
	}
}

struct VariableLengthInteger(u64);
impl VariableLengthInteger {
	pub fn new(n: u64) -> Self {
		VariableLengthInteger(n)
	}

	fn decode(buf: &[u8]) -> Result<(u64, usize)> {
		let b = buf.first().ok_or(Error::DecodeError)?;
		let t = *b >> 6;
		match t {
			0 => Ok((*b as u64, 1)),
			1 => Ok((
				((1u16 << 14) ^ NetworkEndian::read_u16(&buf[0..2])) as u64,
				2,
			)),
			2 => Ok((
				((1u32 << 30) ^ NetworkEndian::read_u32(&buf[0..4])) as u64,
				4,
			)),
			3 => Ok((
				((1u64 << 62) ^ NetworkEndian::read_u64(&buf[0..8])) as u64,
				8,
			)),
			_ => Err(Error::DecodeError),
		}
	}

	pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
		// なぜ buf: &mut [u8] を取るか？
		// なぜ Vec<u8> を返さないか？
		// => byteorder が Read/Write のインタフェースっぽくなっている
		// Vec だと、一旦中で mut slice を作って、書き込んで、vec に変換して、サイズを調整して、返す
		// それなら buf もらって、書き込んで、サイズを返したほうがコード量少なくなる

		// VariableLengthInteger のインスタンスにする必要ある？
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
