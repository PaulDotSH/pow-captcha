- Builder pattern for structs with compile time invariant checks
- Signing
- Store
- Feature based compilation


Implement the store and verification of captcha parameters in both
`impl<T: crate::store::Store> crate::pow::PoW<T> for PoW<T>`

You need to change the error type to PoWError or something  and add bcrypt in that.

In PoW<T> with datastore verify when calling validate_captcha using the store
