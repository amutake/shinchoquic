use std::result;

#[derive(Debug)]
pub enum Error {
	EncodeError,
	DecodeError,
	EncryptError,
	DecryptError,
	NoKeyError,
	NotSupportedError,
}

pub type Result<T> = result::Result<T, Error>;
