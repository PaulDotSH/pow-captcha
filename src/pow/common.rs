use std::future::Future;
use rand::seq::IteratorRandom;
use crate::common::{CaptchaServerInfo, CaptchaType, TokenSignature};
#[cfg(feature = "serialize")]
use crate::pow::DeserializeError;
#[cfg(feature = "serialize")]
use base64::{Engine, prelude::BASE64_STANDARD};
use bitcode::Error;
use crate::store::StoreResult;

pub fn generate_token(length: usize) -> String {
    let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| charset.chars().choose(&mut rng).unwrap())
        .collect()
}

#[cfg(feature = "serialize")]
pub(crate) fn deserialize_captcha_info(string: &str) -> Result<CaptchaServerInfo, DeserializeError> {
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

#[cfg(feature = "serialize")]
#[cfg(feature = "store")]
#[cfg(feature = "async")]
pub(crate) async fn store_captcha<T: crate::store::Store>(mut store: T, captcha_info: &CaptchaServerInfo) -> StoreResult<()> {
    match &captcha_info.client_info.token_signature {
        TokenSignature::Neither => {
            StoreResult::Ok(())
        }
        TokenSignature::Token(t) => {
            let encoded = bitcode::encode(captcha_info);
            match store.set(t, encoded).await {
                StoreResult::Ok(_) => {
                    StoreResult::Ok(())
                }
                StoreResult::RedisError(e) => {
                    StoreResult::RedisError(e)
                }
                StoreResult::GenericError => {
                    StoreResult::GenericError
                }
            }
        }
    }
}

#[cfg(feature = "serialize")]
#[cfg(feature = "store")]
#[cfg(not(feature = "async"))]
pub(crate) fn store_captcha<T: crate::store::Store>(mut store: T, captcha_info: &CaptchaServerInfo) -> StoreResult<()> {
    match &captcha_info.client_info.token_signature {
        TokenSignature::Neither => {
            StoreResult::Ok(())
        }
        TokenSignature::Token(t) => {
            let encoded = bitcode::encode(captcha_info);
            match store.set(t, encoded) {
                StoreResult::Ok(_) => {
                    StoreResult::Ok(())
                }
                StoreResult::RedisError(e) => {
                    StoreResult::RedisError(e)
                }
                StoreResult::GenericError => {
                    StoreResult::GenericError
                }
            }
        }
    }
}


#[cfg(feature = "serialize")]
#[cfg(feature = "store")]
#[cfg(feature = "async")]
pub(crate) async fn verify_captcha_validity<T: crate::store::Store>(mut store: T, captcha_info: &CaptchaServerInfo) -> StoreResult<bool> {
    match &captcha_info.client_info.token_signature {
        TokenSignature::Neither => { StoreResult::Ok(false) }
        TokenSignature::Token(token) => {
            match store.get(&token).await {
                StoreResult::Ok(v) => {
                    let decoded = match bitcode::decode::<CaptchaServerInfo>(&v) {
                        Ok(decoded) => decoded,
                        Err(e) => {
                            return StoreResult::GenericError
                        }
                    };
                    match decoded.client_info.captcha_type {
                        CaptchaType::Exact => {
                            StoreResult::Ok(*captcha_info == decoded)
                        }
                        CaptchaType::Prefix => {
                            StoreResult::Ok(captcha_info.client_info == decoded.client_info)
                        }
                    }
                }
                StoreResult::RedisError(e) => { StoreResult::RedisError(e) }
                _ => { StoreResult::Ok(false) }
            }
        }
    }
}

#[cfg(feature = "serialize")]
#[cfg(feature = "store")]
#[cfg(not(feature = "async"))]
pub(crate) fn verify_captcha_validity<T: crate::store::Store>(mut store: T, captcha_info: &CaptchaServerInfo) -> StoreResult<bool> {
    match &captcha_info.client_info.token_signature {
        TokenSignature::Neither => { StoreResult::Ok(false) }
        TokenSignature::Token(token) => {
            match store.get(&token) {
                StoreResult::Ok(v) => {
                    let decoded = match bitcode::decode::<CaptchaServerInfo>(&v) {
                        Ok(decoded) => decoded,
                        Err(e) => {
                            return StoreResult::GenericError
                        }
                    };
                    match decoded.client_info.captcha_type {
                        CaptchaType::Exact => {
                            StoreResult::Ok(*captcha_info == decoded)
                        }
                        CaptchaType::Prefix => {
                            StoreResult::Ok(captcha_info.client_info == decoded.client_info)
                        }
                    }
                }
                StoreResult::RedisError(e) => { StoreResult::RedisError(e) }
                _ => { StoreResult::Ok(false) }
            }
        }
    }
}