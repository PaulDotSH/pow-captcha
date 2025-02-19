use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use bcrypt::BcryptError;
use rand::{rng, Rng};
use crate::common;
use crate::common::{CaptchaAnswer, CaptchaClientInfo, CaptchaServerInfo};
use crate::pow::common::generate_token;
use super::{CaptchaInput, PoWCommon};
#[cfg(feature = "serialize")]
use super::DeserializeError;


pub trait PoWImpl {
    fn generate_captcha(&self) -> Result<CaptchaAnswer, BcryptError> {
        let mut rng = rng();
        let salt: String = (0..self.salt_size())
            .map(|_| rng.random_range(b'a'..=b'z') as char)
            .collect();
    
        let nonce: u64 = rng.random_range(0..self.common().challenge_size);
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
            ts = TokenSignature::Token(generate_token(self.common().token_size));
        }

        #[cfg(feature = "signing")]
        {
            ts = TokenSignature::TokenSignature((generate_token(self.common().token_size), String::from("signature todo")));
        }

        let info = CaptchaClientInfo {
            hash: captcha.hash.clone(),
            salt: captcha.salt.clone(),
            captcha_type: CaptchaType::Exact,
            size: self.common().challenge_size as usize,
            cost: self.common().cost,
            token_signature: ts,
        };

        let encoded: Vec<u8> = bitcode::encode(&info);

        Ok((base64::prelude::BASE64_STANDARD.encode(encoded), captcha))
    }

    #[cfg(feature = "serialize")]
    fn deserialize_captcha_info(&self, string: &str) -> Result<CaptchaServerInfo, DeserializeError> {
        let decoded_b64 = match BASE64_STANDARD.decode(string) {
            Ok(decoded) => decoded,
            Err(e) => {
                return Err(DeserializeError::Base64Error(e));
            }
        };

        let captcha_info: CaptchaServerInfo = match bitcode::decode::<CaptchaServerInfo>(&decoded_b64) {
            Ok(decoded) => decoded,
            Err(e) => {
                return Err(DeserializeError::BitcodeError(e));
            }
        };

        Ok(captcha_info)
    }


    #[cfg(feature = "store")]
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
#[cfg(feature = "async")]
#[async_trait::async_trait]
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
        let captcha = PoWImpl::generate_captcha(self)?;
    }

    fn validate_captcha(&self, input: CaptchaInput) -> bool {
        PoWImpl::validate_captcha(self, input)
    }

    #[cfg(feature = "serialize")]
    fn deserialize_captcha_server_info(&self, string: &str) -> Result<CaptchaServerInfo, DeserializeError> {
        PoWImpl::deserialize_captcha_info(self, string)
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
