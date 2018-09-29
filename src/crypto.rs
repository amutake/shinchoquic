use rustls::quic::{Keys, Side};

use packet::ConnectionId;

pub const AUTH_TAG_LEN: usize = 16;
pub const PN_SAMPLE_LEN: usize = 16;

#[derive(Debug, Clone)]
pub struct PhaseKeys {
	pub initial: Option<Keys>,
	pub zero_rtt: Option<Keys>,
	pub handshake: Option<Keys>,
	pub one_rtt: Option<Keys>,
}

impl PhaseKeys {
	pub fn new(dst_conn_id: &ConnectionId) -> Self {
		PhaseKeys {
			// クライアントのみサポート
			initial: Some(Keys::initial(&dst_conn_id.inner(), Side::Client)),
			zero_rtt: None,
			handshake: None,
			one_rtt: None,
		}
	}

	pub fn set_initial(&mut self, keys: Keys) {
		self.initial = Some(keys);
	}

	pub fn set_handshake(&mut self, keys: Keys) {
		self.handshake = Some(keys);
	}

	pub fn set_one_rtt(&mut self, keys: Keys) {
		self.one_rtt = Some(keys);
	}
}
