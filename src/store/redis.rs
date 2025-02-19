#[cfg(feature = "store-redis")]
use redis::{Client, RedisResult};
use crate::store::{Store, StoreResult};
#[cfg(feature = "async")]
use redis::AsyncCommands;
#[cfg(not(feature = "async"))]
use redis::Commands;


#[cfg(feature = "store-redis")]
pub struct RedisStore {
    #[cfg(feature = "async")]
    connection: redis::aio::MultiplexedConnection,
    #[cfg(not(feature = "async"))]
    connection: redis::Connection,
    client: Client,
}

// TODO: Add pooling
// TODO: Add cluster support

#[cfg(feature = "async")]
impl RedisStore {
    pub async fn new(url: &str) -> RedisResult<Self> {
        let client = Client::open(url)?;
        Ok(RedisStore { connection: client.get_multiplexed_async_connection().await?, client })
    }
}

#[cfg(feature = "async")]
#[async_trait::async_trait]
impl Store for RedisStore {
    async fn get(&mut self, key: &str) -> StoreResult<Vec<u8>> {
        match self.connection.get::<&str, Vec<u8>>(key).await {
            Ok(s) => {
                StoreResult::Ok(s)
            }
            Err(e) => {
                StoreResult::RedisError(e)
            }
        }
    }

    async fn set(&mut self, key: &str, value: Vec<u8>) -> StoreResult<()> {
        match self.connection.set::<&str, Vec<u8>, ()>(key, value).await {
            Ok(_) => {
                StoreResult::Ok(())
            }
            Err(e) => {
                StoreResult::RedisError(e)
            }
        }
    }
}


#[cfg(not(feature = "async"))]
impl RedisStore {
    pub fn new(url: &str) -> RedisResult<Self> {
        let client = Client::open(url)?;
        Ok(RedisStore { connection: client.get_connection()?, client })
    }

}
#[cfg(not(feature = "async"))]
impl Store for RedisStore {
    fn get(&mut self, key: &str) -> StoreResult<Vec<u8>> {
        match self.connection.get::<&str, Vec<u8>>(key) {
            Ok(s) => {
                StoreResult::Ok(s)
            }
            Err(e) => {
                StoreResult::RedisError(e)
            }
        }
    }

    fn set(&mut self, key: &str, value: Vec<u8>) -> StoreResult<()> {
        match self.connection.set::<&str, Vec<u8>, ()>(key, value) {
            Ok(s) => {
                StoreResult::Ok(s)
            }
            Err(e) => {
                StoreResult::RedisError(e)
            }
        }
    }
}