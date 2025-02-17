use bcrypt::BcryptError;
use rand::{rng, Rng};

use super::{CaptchaAnswer, CaptchaInput};

pub struct PoW {
    pub cost: u32,
    pub challenge_size: u64,
    pub salt_size: u16,
}

impl crate::pow::PoW for PoW {
    fn generate_captcha(&self) -> Result<CaptchaAnswer, BcryptError> {
        let salt: String = (0..self.salt_size)
            .map(|_| rng().random_range(b'a'..=b'z') as char)
            .collect();
    
        let nonce: u64 = rng().random_range(0..self.challenge_size);
        let nonce_str = nonce.to_string();
    
        let to_hash = format!("{}{}", salt, nonce_str);
    
        let hash = bcrypt::hash(&to_hash, self.cost)?;
    
        Ok(CaptchaAnswer {
            nonce,
            hash,
            salt,
        })
    }

    fn validate_captcha(&self, input: CaptchaInput) -> bool {
        let to_hash = format!("{}{}", input.salt, input.nonce);
        bcrypt::verify(&to_hash, &input.hash).unwrap_or(false)
    }
}