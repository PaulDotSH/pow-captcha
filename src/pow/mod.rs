use bcrypt::BcryptError;

pub mod prefix;
pub mod exact;

pub trait PoW {
    fn generate_captcha(&self) -> Result<CaptchaAnswer, BcryptError>;
    fn validate_captcha(&self, input: CaptchaInput) -> bool;
}

#[derive(Debug)]
pub struct CaptchaAnswer {
    pub nonce: u64,
    pub hash: String,
    pub salt: String,
}

#[derive(Debug)]
pub struct CaptchaInput {
    pub nonce: u64,
    pub hash: String,
    pub salt: String,
}