//! Create and parses JWT (JSON Web Tokens)
//!
//! Documentation:  [stable](https://docs.rs/jsonwebtoken/)
//#![deny(missing_docs)]

mod algorithms;
/// Lower level functions, if you want to do something other than JWTs
pub mod crypto;
mod decoding;
mod encoding;
/// All the errors that can be encountered while encoding/decoding JWTs
pub mod errors;
mod header;
pub mod jwk;
#[cfg(feature = "use_pem")]
mod pem;
mod serialization;
mod validation;

pub use algorithms::Algorithm;
pub use decoding::{decode, decode_header, DecodingKey, TokenData, decode_acl_selective_disclosure};
pub use encoding::{encode, encode_acl, new_local_pvd, PreToken, get_acl_pretoken_full_disclosure, EncodingKey, LocalPVD, SignatureProvider};
pub use header::Header;
pub use validation::{get_current_timestamp, Validation};
