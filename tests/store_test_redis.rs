#[cfg(feature = "store-redis")]
use pow_captcha::{store, store::{Store, StoreResult}};

#[cfg(feature = "store-redis")]
#[cfg(feature = "async")]
#[tokio::test]
async fn async_test_connect_to_redis() {
    let mut store = store::redis::RedisStore::new("redis://127.0.0.1:6379/").await.unwrap();
    let vec = vec![1, 2, 3, 4, 5];
    store.set("key".into(), vec.clone()).await;
    let val = store.get("key".into()).await;
    match val {
        StoreResult::Ok(val) => {
            assert_eq!(val, vec);
        }
        StoreResult::RedisError(e) => {
            assert!(false)
        }
    }
}

#[cfg(feature = "store-redis")]
#[cfg(not(feature = "async"))]
#[test]
fn test_connect_to_redis() {
    let mut store = store::redis::RedisStore::new("redis://127.0.0.1:6379/").unwrap();
    let vec = vec![1, 2, 3, 4, 5];
    store.set("key".into(), vec.clone()).await;
    let val = store.get("key".into());
    match val {
        StoreResult::Ok(val) => {
            assert_eq!(val, vec);
        }
        StoreResult::RedisError(e) => {
            assert!(false)
        }
    }
}