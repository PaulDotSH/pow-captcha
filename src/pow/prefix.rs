use std::clone;

use bcrypt::BcryptError;
use rand::{rng, Rng};
use crate::common::CaptchaAnswer;
use super::{CaptchaInput, PoWCommon};

#[cfg(feature = "store")]
pub struct PoW<T: crate::store::Store> {
    pub common: PoWCommon,
    pub match_size: usize,
    pub store: T,
}

#[cfg(not(feature = "store"))]
pub struct PoW {
    pub common: PoWCommon,
    pub match_size: usize,
}

impl crate::pow::PoW for PoW {
    fn generate_captcha(&self) -> Result<CaptchaAnswer, BcryptError> {
        let salt: String = (0..self.common.challenge_size)
            .map(|_| rng().random_range(b'a'..=b'z') as char)
            .collect();
    
        let nonce: u64 = rng().random_range(0..self.common.challenge_size);
        let nonce_str = nonce.to_string();
    
        let to_hash = format!("{}{}", salt, nonce_str);

        // TODO: Ensure the min length is 16 when switching to builder pattern
        let bcrypt_salt = salt[0..16].as_bytes();
    
        let hash = bcrypt::hash_with_salt(&to_hash, self.common.cost, bcrypt_salt.try_into().unwrap())?.to_string();
    
        Ok(CaptchaAnswer {
            nonce,
            hash,
            salt,
        })
    }

    fn validate_captcha(&self, input: CaptchaInput) -> bool {
        let to_hash = format!("{}{}", input.salt, input.nonce);

        let bcrypt_salt = input.salt[0..16].as_bytes();

        let hash = match bcrypt::hash_with_salt(&to_hash, self.common.cost, bcrypt_salt.try_into().unwrap()) {
            Ok(h) => h,
            Err(_) => return false,
        };

        hash.to_string().as_bytes().iter().take(self.match_size).zip(input.hash.as_bytes().iter().take(self.match_size)).all(|(a, b)| a == b)
    }
    
    #[cfg(feature = "serialize")]
    fn generate_serialized_captcha(&self) -> Result<(String, CaptchaAnswer), BcryptError> {
        use base64::Engine;

        use crate::common::{CaptchaClientInfo, CaptchaType, TokenSignature};

        let captcha = self.generate_captcha()?;

        let mut ts = TokenSignature::Neither;
        #[cfg(feature = "store")]
        {
            // TODO: Insert into store
            ts = TokenSignature::Token();
        }

        #[cfg(feature = "signing")]
        {
            // TODO: Sign
            ts = TokenSignature::Signature();
        }

        let info = CaptchaClientInfo {
            hash: captcha.hash.clone(),
            salt: captcha.salt.clone(),
            captcha_type: CaptchaType::Prefix,
            size: self.match_size,
            cost: self.common.cost,
            tokensignature: ts,
        };

        let encoded: Vec<u8> = bitcode::encode(&info);

        Ok((base64::prelude::BASE64_STANDARD.encode(encoded), captcha))
    }

}