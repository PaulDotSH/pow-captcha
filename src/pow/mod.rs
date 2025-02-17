use bcrypt::BcryptError;

use crate::common::CaptchaAnswer;

pub mod prefix;
pub mod exact;

pub trait PoW {
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
}

#[derive(Debug)]
pub struct CaptchaInput {
    pub nonce: u64,
    pub hash: String,
    pub salt: String,
}