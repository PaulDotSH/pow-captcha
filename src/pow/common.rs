use rand::seq::IteratorRandom;
use crate::common::CaptchaServerInfo;
#[cfg(feature = "serialize")]
use crate::pow::DeserializeError;
#[cfg(feature = "serialize")]
use base64::{Engine, prelude::BASE64_STANDARD};

pub fn generate_token(length: usize) -> String {
    let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| charset.chars().choose(&mut rng).unwrap())
        .collect()
}

#[cfg(feature = "serialize")]
fn deserialize_captcha_info(string: &str) -> Result<CaptchaServerInfo, DeserializeError> {
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