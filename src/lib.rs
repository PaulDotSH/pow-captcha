pub mod pow;

#[cfg(feature = "signing")]
pub mod signing;

#[cfg(feature = "signing")]
pub mod store;

#[cfg(test)]
mod tests {
    use crate::pow::{CaptchaInput, PoW};

    use super::*;

    #[test]
    fn test_exact_captcha() {
        let instance = pow::exact::PoW {
            cost: 12,
            challenge_size: 350,
            salt_size: 32,
        };
        let captcha = instance.generate_captcha().unwrap();
        println!("{:?}", captcha);

        assert!(instance.validate_captcha(CaptchaInput{ salt: captcha.salt, hash: captcha.hash, nonce: captcha.nonce }))
    }

    #[test]
    fn test_prefix_captcha() {
        let instance = pow::prefix::PoW {
            cost: 12,
            challenge_size: 32,
            match_size: 36,
        };
        let mut captcha = instance.generate_captcha().unwrap();

        captcha.hash.replace_range((36..40), "abcd");

        assert!(instance.validate_captcha(CaptchaInput{ salt: captcha.salt, hash: captcha.hash, nonce: captcha.nonce }))
    }

    #[test]
    fn test_prefix_captcha_fail() {
        let instance = pow::prefix::PoW {
            cost: 12,
            challenge_size: 32,
            match_size: 36,
        };
        let mut captcha = instance.generate_captcha().unwrap();

        captcha.hash.replace_range((30..36), "abcdef");

        assert!(!instance.validate_captcha(CaptchaInput{ salt: captcha.salt, hash: captcha.hash, nonce: captcha.nonce }))
    }
}
