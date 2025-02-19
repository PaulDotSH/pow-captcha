use rand::seq::IteratorRandom;

pub fn generate_token(length: usize) -> String {
    let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| charset.chars().choose(&mut rng).unwrap())
        .collect()
}