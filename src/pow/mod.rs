use bcrypt::BcryptError;
use crate::common::{CaptchaAnswer, CaptchaClientInfo, CaptchaServerInfo};

pub mod prefix;
pub mod exact;
mod common;

#[cfg(not(feature = "store"))]
pub trait PoW {
    fn generate_captcha(&self) -> Result<CaptchaAnswer, BcryptError>;
    fn validate_captcha(&self, input: CaptchaInput) -> bool;
    #[cfg(feature = "serialize")]
    fn generate_serialized_captcha(&self) -> Result<(String, CaptchaAnswer), BcryptError>;
}

#[cfg(feature = "serialize")]
enum DeserializeError {
    BitcodeError(bitcode::Error),
    Base64Error(base64::DecodeError),
}

#[cfg(feature = "store")]
pub trait PoW<T> {
    fn generate_captcha(&self) -> Result<CaptchaAnswer, BcryptError>;
    fn validate_captcha(&self, input: CaptchaInput) -> bool;
    #[cfg(feature = "serialize")]
    fn generate_serialized_captcha(&self) -> Result<(String, CaptchaAnswer), BcryptError>;
}

#[cfg(feature = "serialize")]
use bitcode::{Encode, Decode};

#[derive(Clone)]
#[cfg_attr(feature = "serialize", derive(Encode, Decode))]
pub struct PoWCommon {
    pub cost: u32,
    pub challenge_size: u64,
    #[cfg(feature = "store")]
    pub token_size: usize,
}

#[derive(Debug)]
pub struct CaptchaInput {
    pub nonce: u64,
    pub hash: String,
    pub salt: String,
}