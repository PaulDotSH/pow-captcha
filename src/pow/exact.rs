use bcrypt::BcryptError;
use rand::{thread_rng, Rng};
use crate::common::CaptchaAnswer;
use super::{CaptchaInput, PoWCommon};

pub trait PoWImpl {
    fn generate_captcha(&self) -> Result<CaptchaAnswer, BcryptError> {
        let mut rng = thread_rng();
        let salt: String = (0..self.salt_size())
            .map(|_| rng.gen_range(b'a'..=b'z') as char)
            .collect();
    
        let nonce: u64 = rng.gen_range(0..self.common().challenge_size);
        let nonce_str = nonce.to_string();
    
        let to_hash = format!("{}{}", salt, nonce_str);
    
        let hash = bcrypt::hash(&to_hash, self.common().cost)?;
    
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
    
    #[cfg(feature = "serialize")]
    fn generate_serialized_captcha(&self) -> Result<(String, CaptchaAnswer), BcryptError> {
        use base64::Engine;
        use crate::common::{CaptchaClientInfo, CaptchaType, TokenSignature};

        let captcha = self.generate_captcha()?;
        let mut ts = TokenSignature::Neither;

        #[cfg(feature = "store")]
        {
            ts = TokenSignature::Token();
        }

        #[cfg(feature = "signing")]
        {
            ts = TokenSignature::Signature();
        }

        let info = CaptchaClientInfo {
            hash: captcha.hash.clone(),
            salt: captcha.salt.clone(),
            captcha_type: CaptchaType::Exact,
            size: self.common().challenge_size as usize,
            cost: self.common().cost,
            tokensignature: ts,
        };

        let encoded: Vec<u8> = bitcode::encode(&info);

        Ok((base64::prelude::BASE64_STANDARD.encode(encoded), captcha))
    }

    fn common(&self) -> &PoWCommon;
    fn salt_size(&self) -> u16;
}

#[cfg(feature = "store")]
pub struct PoW<T: crate::store::Store> {
    pub common: PoWCommon,
    pub salt_size: u16,
    pub store: T,
}

#[cfg(not(feature = "store"))]
pub struct PoW {
    pub common: PoWCommon,
    pub salt_size: u16,
}

#[cfg(feature = "store")]
impl<T: crate::store::Store> PoWImpl for PoW<T> {
    fn common(&self) -> &PoWCommon {
        &self.common
    }
    fn salt_size(&self) -> u16 {
        self.salt_size
    }
}

#[cfg(not(feature = "store"))]
impl PoWImpl for PoW {
    fn common(&self) -> &PoWCommon {
        &self.common
    }
    fn salt_size(&self) -> u16 {
        self.salt_size
    }
}

#[cfg(feature = "store")]
impl<T: crate::store::Store> crate::pow::PoW<T> for PoW<T> {
    fn generate_captcha(&self) -> Result<CaptchaAnswer, BcryptError> {
        PoWImpl::generate_captcha(self)
    }

    fn validate_captcha(&self, input: CaptchaInput) -> bool {
        PoWImpl::validate_captcha(self, input)
    }

    #[cfg(feature = "serialize")]
    fn generate_serialized_captcha(&self) -> Result<(String, CaptchaAnswer), BcryptError> {
        PoWImpl::generate_serialized_captcha(self)
    }
}

#[cfg(not(feature = "store"))]
impl crate::pow::PoW for PoW {
    fn generate_captcha(&self) -> Result<CaptchaAnswer, BcryptError> {
        PoWImpl::generate_captcha(self)
    }

    fn validate_captcha(&self, input: CaptchaInput) -> bool {
        PoWImpl::validate_captcha(self, input)
    }

    #[cfg(feature = "serialize")]
    fn generate_serialized_captcha(&self) -> Result<(String, CaptchaAnswer), BcryptError> {
        PoWImpl::generate_serialized_captcha(self)
    }
}
