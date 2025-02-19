#[cfg(feature = "store-redis")]
pub mod redis;

#[derive(Debug)]
pub enum StoreResult<T> {
    Ok(T),
    #[cfg(feature = "store-redis")]
    RedisError(::redis::RedisError),
}

#[cfg(feature = "async")]
#[async_trait::async_trait]
pub trait Store {
    async fn get(&mut self, key: String) -> StoreResult<Vec<u8>>;
    async fn set(&mut self, key: String, value: Vec<u8>) -> StoreResult<()>;
}


#[cfg(not(feature = "async"))]
pub trait Store {
    fn get(&mut self, key: String) -> StoreResult<String>;
    fn set(&mut self, key: String, value: Vec<u8>) -> StoreResult<()>;
}

/*
    Workflow

    Think of an api that will send each user a token to know which params they have so they cant be modified client side
*/