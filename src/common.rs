#[derive(Debug)]
#[cfg(feature = "serialize")]
#[derive(bitcode::Encode, bitcode::Decode)]
pub struct CaptchaAnswer {
    pub nonce: u64,
    pub hash: String,
    pub salt: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg(feature = "serialize")]
#[derive(bitcode::Encode, bitcode::Decode)]
pub enum CaptchaType {
    Exact,
    Prefix,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg(feature = "serialize")]
#[derive(bitcode::Encode, bitcode::Decode)]
// Token and signature are always here since the client should be portable
pub struct CaptchaClientInfo {
    pub token_signature: TokenSignature,
    pub hash: String,
    pub salt: String,
    pub captcha_type: CaptchaType,
    pub size: usize,
    pub cost: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg(feature = "serialize")]
#[derive(bitcode::Encode, bitcode::Decode)]
pub enum TokenSignature{
    Neither,
    Token(String),
}

#[derive(Debug, Eq, PartialEq)]
#[cfg(feature = "serialize")]
#[derive(bitcode::Encode, bitcode::Decode)]
pub struct CaptchaServerInfo {
    pub client_info: CaptchaClientInfo,
    pub nonce: u64
} 