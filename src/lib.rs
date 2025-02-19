pub mod pow;

#[cfg(feature = "signing")]
pub mod signing;

#[cfg(feature = "store")]
pub mod store;

pub mod common;

#[cfg(test)]
mod tests {
    use std::process::Command;

    use base64::{prelude::BASE64_STANDARD, Engine};

    use crate::pow::{CaptchaInput, PoW, PoWCommon};

    use super::*;

    #[cfg(not(feature = "store"))]
    #[test]
    fn test_exact_captcha() {
        #[cfg(not(feature = "store"))]
        let instance = pow::exact::PoW {
            salt_size: 32,
            common: PoWCommon {
                cost: 12,
                challenge_size: 350,
            },
        };

        let (encoded, captcha) = instance.generate_serialized_captcha().unwrap();
        println!("{:?}", encoded);
        println!("{:?}", captcha);

        assert!(instance.validate_captcha(CaptchaInput{ salt: captcha.salt, hash: captcha.hash, nonce: captcha.nonce }))
    }

    #[cfg(not(feature = "store"))]
    #[test]
    fn test_prefix_captcha_cli() {
        let instance = pow::exact::PoW {
            salt_size: 32,
            common: PoWCommon {
                cost: 12,
                challenge_size: 350,
            },
        };
        let (encoded, mut captcha) = instance.generate_serialized_captcha().unwrap();

        let output = Command::new("cargo")
        .arg("run")
        .arg("--release")
        .arg("--bin")
        .arg("pow-captcha-cli")
        .arg("--")
        .arg(encoded)
        .output()
        .expect("Failed to execute command");
        let output = String::from_utf8(output.stdout).unwrap();

        let encoded = output.split('\n').collect::<Vec<&str>>();
        let encoded = encoded[encoded.len()-2];

        let decodedb64 = BASE64_STANDARD.decode(encoded).expect("Invalid encoded string");
        let captcha_info: common::CaptchaServerInfo
            = bitcode::decode(&decodedb64).expect("failed to decode captcha answer and type");
        println!("{:?}", captcha_info);

        assert!(instance.validate_captcha(CaptchaInput{ salt: captcha_info.client_info.salt, hash: captcha_info.client_info.hash,
            nonce: captcha_info.nonce }))
    }

    #[cfg(not(feature = "store"))]
    #[test]
    fn test_exact_captcha_cli() {
        let instance = pow::exact::PoW {
            salt_size: 32,
            common: PoWCommon {
                cost: 12,
                challenge_size: 350,
            },
        };
        let (encoded, mut captcha) = instance.generate_serialized_captcha().unwrap();

        let output = Command::new("cargo")
        .arg("run")
        .arg("--release")
        .arg("--bin")
        .arg("pow-captcha-cli")
        .arg("--")
        .arg(encoded)
        .output()
        .expect("Failed to execute command");
        let output = String::from_utf8(output.stdout).unwrap();

        let encoded = output.split('\n').collect::<Vec<&str>>();
        let encoded = encoded[encoded.len()-2];

        let decodedb64 = BASE64_STANDARD.decode(encoded).expect("Invalid encoded string");
        let captcha_info: common::CaptchaServerInfo
            = bitcode::decode(&decodedb64).expect("failed to decode captcha answer and type");
        println!("{:?}", captcha_info);

        assert!(instance.validate_captcha(CaptchaInput{ salt: captcha_info.client_info.salt, hash: captcha_info.client_info.hash,
            nonce: captcha_info.nonce }))
    }

    #[cfg(not(feature = "store"))]
    #[test]
    fn test_prefix_captcha_fail() {
        let instance = pow::prefix::PoW {
            common: PoWCommon {
                cost: 12,
                challenge_size: 32,
            },
            match_size: 36,
        };

        let mut captcha = instance.generate_captcha().unwrap();

        captcha.hash.replace_range(30..36, "abcdef");

        assert!(!instance.validate_captcha(CaptchaInput{ salt: captcha.salt, hash: captcha.hash, nonce: captcha.nonce }))
    }
}
