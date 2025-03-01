use std::env;

use base64::prelude::*;
use pow_captcha::common::{CaptchaClientInfo, CaptchaServerInfo, CaptchaType};
use rayon::prelude::*;

fn main() {
    let Some(b64encoded) = env::args().nth(1) else {
        eprintln!("Usage: {} captcha_str", env::args().next().unwrap());
        return;
    };

    let decodedb64 = BASE64_STANDARD.decode(b64encoded).expect("Invalid encoded string");
    let captcha_info: CaptchaClientInfo
        = bitcode::decode(&decodedb64).expect("failed to decode captcha answer and type");

    match captcha_info.captcha_type {
        CaptchaType::Exact => solve_exact_captcha(captcha_info),
        CaptchaType::Prefix => solve_prefix_captcha(captcha_info),
    }
}

pub fn solve_exact_captcha(info: CaptchaClientInfo) {
    println!("Generating from 0 to {}", info.size);

    (0..=info.size).into_par_iter().for_each(|nonce: usize| {
        let to_hash = format!("{}{}", info.salt, nonce);
        
        if bcrypt::verify(&to_hash, &info.hash).unwrap() {
            println!("Nonce found {}", nonce);
            let info = CaptchaServerInfo {
                client_info: CaptchaClientInfo { token_signature: info.token_signature.clone(), hash: info.hash.clone(), salt: info.salt.clone(), captcha_type: info.captcha_type, size: info.size, cost: info.cost },
                nonce: nonce as u64,
            };
            
            let encoded_info = bitcode::encode(&info);

            let encoded_b64 = BASE64_STANDARD.encode(encoded_info);
            println!("{}", encoded_b64);
            std::process::exit(0);
        }
    });
    println!("No nonce found");
}

pub fn solve_prefix_captcha(info: CaptchaClientInfo) {
    println!("Generating from 0 to {}", 100_000);
    (0..=100_000).into_par_iter().for_each(|nonce| {
        let to_hash = format!("{}{}", info.salt, nonce);
        let hash = bcrypt::hash_with_salt(&to_hash, info.cost,
            info.salt.as_bytes()[0..16].try_into().expect("Cannot into")).expect("Cannot hash").to_string();
        
        if hash.to_string().as_bytes().iter().take(info.size).zip(info.hash.as_bytes().iter().take(info.size)).all(|(a, b)| a == b) {
            println!("Nonce found {}", nonce);

            println!("Verifying...");

            let info = CaptchaServerInfo {
                client_info: CaptchaClientInfo { token_signature: info.token_signature.clone(), hash: info.hash.clone(), salt: info.salt.clone(), captcha_type: info.captcha_type, size: info.size, cost: info.cost },
                nonce: nonce as u64,
            };
            
            let encoded_info = bitcode::encode(&info);

            let encoded_b64 = BASE64_STANDARD.encode(encoded_info);
            println!("{}", encoded_b64);
            std::process::exit(0);
        }
    });
    println!("No nonce found");
}