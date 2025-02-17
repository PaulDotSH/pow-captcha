use std::io::Read;

use bcrypt::BcryptError;
use rand::{rng, Rng};

use super::{CaptchaAnswer, CaptchaInput};

pub struct PoW {
    pub cost: u32,
    pub challenge_size: u64,
    pub match_size: usize,
}

impl crate::pow::PoW for PoW {
    fn generate_captcha(&self) -> Result<CaptchaAnswer, BcryptError> {
        let salt: String = (0..self.challenge_size)
            .map(|_| rng().random_range(b'a'..=b'z') as char)
            .collect();
    
        let nonce: u64 = rng().random_range(0..self.challenge_size);
        let nonce_str = nonce.to_string();
    
        let to_hash = format!("{}{}", salt, nonce_str);

        let bcrypt_salt = salt[0..16].as_bytes();
    
        let hash = bcrypt::hash_with_salt(&to_hash, self.cost, bcrypt_salt.try_into().unwrap())?.to_string();
    
        Ok(CaptchaAnswer {
            nonce,
            hash,
            salt,
        })
    }

    fn validate_captcha(&self, input: CaptchaInput) -> bool {
        let to_hash = format!("{}{}", input.salt, input.nonce);

        let bcrypt_salt = input.salt[0..16].as_bytes();

        let hash = match bcrypt::hash_with_salt(&to_hash, self.cost, bcrypt_salt.try_into().unwrap()) {
            Ok(h) => h,
            Err(_) => return false,
        };

        hash.to_string().as_bytes().iter().take(self.match_size).zip(input.hash.as_bytes().iter().take(self.match_size)).all(|(a, b)| a == b)
    }
}