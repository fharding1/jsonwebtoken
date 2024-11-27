use std::str::FromStr;

use acl::{gen_z, Signature, UserParameters, VerifyingKey};
use base64::alphabet::URL_SAFE;
use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::RistrettoPoint;
use okamoto::{verify_dleq, verify_linear};
use serde::de::DeserializeOwned;
use std::time::Instant;

use crate::algorithms::AlgorithmFamily;
use crate::crypto::verify;
use crate::encoding::{AclPayload,gen_h0};
use crate::encoding::{key_to_generator, value_to_scalar};
use crate::errors::{new_error, ErrorKind, Result};
use crate::header::Header;
use crate::jwk::{AlgorithmParameters, Jwk};
#[cfg(feature = "use_pem")]
use crate::pem::decoder::PemEncodedKey;
use crate::serialization::{b64_decode, DecodedJwtPartClaims};
use crate::validation::{validate, Validation};
use std::hash::Hash;

/// The return type of a successful call to [decode](fn.decode.html).
#[derive(Debug)]
pub struct TokenData<T> {
    /// The decoded JWT header
    pub header: Header,
    /// The decoded JWT claims
    pub claims: T,
}

impl<T> Clone for TokenData<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self { header: self.header.clone(), claims: self.claims.clone() }
    }
}

/// Takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(new_error(ErrorKind::InvalidToken)),
        }
    }};
}

#[derive(Clone)]
pub(crate) enum DecodingKeyKind {
    SecretOrDer(Vec<u8>),
    RsaModulusExponent { n: Vec<u8>, e: Vec<u8> },
    AclVerifyingKey(VerifyingKey),
}

/// All the different kind of keys we can use to decode a JWT.
/// This key can be re-used so make sure you only initialize it once if you can for better performance.
#[derive(Clone)]
pub struct DecodingKey {
    pub(crate) family: AlgorithmFamily,
    pub(crate) kind: DecodingKeyKind,
}

impl DecodingKey {
    pub fn from_acl_vk(vk: VerifyingKey) -> Self {
        DecodingKey { family: AlgorithmFamily::Acl, kind: DecodingKeyKind::AclVerifyingKey(vk) }
    }

    /// If you're using HMAC, use this.
    pub fn from_secret(secret: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Hmac,
            kind: DecodingKeyKind::SecretOrDer(secret.to_vec()),
        }
    }

    /// If you're using HMAC with a base64 encoded secret, use this.
    pub fn from_base64_secret(secret: &str) -> Result<Self> {
        let out = STANDARD.decode(secret)?;
        Ok(DecodingKey { family: AlgorithmFamily::Hmac, kind: DecodingKeyKind::SecretOrDer(out) })
    }

    /// If you are loading a public RSA key in a PEM format, use this.
    /// Only exists if the feature `use_pem` is enabled.
    #[cfg(feature = "use_pem")]
    pub fn from_rsa_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_rsa_key()?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Rsa,
            kind: DecodingKeyKind::SecretOrDer(content.to_vec()),
        })
    }

    /// If you have (n, e) RSA public key components as strings, use this.
    pub fn from_rsa_components(modulus: &str, exponent: &str) -> Result<Self> {
        let n = b64_decode(modulus)?;
        let e = b64_decode(exponent)?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Rsa,
            kind: DecodingKeyKind::RsaModulusExponent { n, e },
        })
    }

    /// If you have (n, e) RSA public key components already decoded, use this.
    pub fn from_rsa_raw_components(modulus: &[u8], exponent: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Rsa,
            kind: DecodingKeyKind::RsaModulusExponent { n: modulus.to_vec(), e: exponent.to_vec() },
        }
    }

    /// If you have a ECDSA public key in PEM format, use this.
    /// Only exists if the feature `use_pem` is enabled.
    #[cfg(feature = "use_pem")]
    pub fn from_ec_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ec_public_key()?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Ec,
            kind: DecodingKeyKind::SecretOrDer(content.to_vec()),
        })
    }

    /// If you have (x,y) ECDSA key components
    pub fn from_ec_components(x: &str, y: &str) -> Result<Self> {
        let x_cmp = b64_decode(x)?;
        let y_cmp = b64_decode(y)?;

        let mut public_key = Vec::with_capacity(1 + x.len() + y.len());
        public_key.push(0x04);
        public_key.extend_from_slice(&x_cmp);
        public_key.extend_from_slice(&y_cmp);

        Ok(DecodingKey {
            family: AlgorithmFamily::Ec,
            kind: DecodingKeyKind::SecretOrDer(public_key),
        })
    }

    /// If you have a EdDSA public key in PEM format, use this.
    /// Only exists if the feature `use_pem` is enabled.
    #[cfg(feature = "use_pem")]
    pub fn from_ed_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ed_public_key()?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Ed,
            kind: DecodingKeyKind::SecretOrDer(content.to_vec()),
        })
    }

    /// If you know what you're doing and have a RSA DER encoded public key, use this.
    pub fn from_rsa_der(der: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Rsa,
            kind: DecodingKeyKind::SecretOrDer(der.to_vec()),
        }
    }

    /// If you know what you're doing and have a RSA EC encoded public key, use this.
    pub fn from_ec_der(der: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Ec,
            kind: DecodingKeyKind::SecretOrDer(der.to_vec()),
        }
    }

    /// If you know what you're doing and have a Ed DER encoded public key, use this.
    pub fn from_ed_der(der: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Ed,
            kind: DecodingKeyKind::SecretOrDer(der.to_vec()),
        }
    }

    /// From x part (base64 encoded) of the JWK encoding
    pub fn from_ed_components(x: &str) -> Result<Self> {
        let x_decoded = b64_decode(x)?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Ed,
            kind: DecodingKeyKind::SecretOrDer(x_decoded),
        })
    }

    /// If you have a key in Jwk format
    pub fn from_jwk(jwk: &Jwk) -> Result<Self> {
        match &jwk.algorithm {
            AlgorithmParameters::RSA(params) => {
                DecodingKey::from_rsa_components(&params.n, &params.e)
            }
            AlgorithmParameters::EllipticCurve(params) => {
                DecodingKey::from_ec_components(&params.x, &params.y)
            }
            AlgorithmParameters::OctetKeyPair(params) => DecodingKey::from_ed_components(&params.x),
            AlgorithmParameters::OctetKey(params) => {
                let out = b64_decode(&params.value)?;
                Ok(DecodingKey {
                    family: AlgorithmFamily::Hmac,
                    kind: DecodingKeyKind::SecretOrDer(out),
                })
            }
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        match &self.kind {
            DecodingKeyKind::SecretOrDer(b) => b,
            DecodingKeyKind::RsaModulusExponent { .. } => unreachable!(),
            DecodingKeyKind::AclVerifyingKey(_) => unreachable!(),
        }
    }
}

/// Verify signature of a JWT, and return header object and raw payload
///
/// If the token or its signature is invalid, it will return an error.
fn verify_signature<'a>(
    token: &'a str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<(Header, &'a str)> {
    if validation.validate_signature && validation.algorithms.is_empty() {
        return Err(new_error(ErrorKind::MissingAlgorithm));
    }

    if validation.validate_signature {
        for alg in &validation.algorithms {
            if key.family != alg.family() {
                return Err(new_error(ErrorKind::InvalidAlgorithm));
            }
        }
    }

    let (signature, message) = expect_two!(token.rsplitn(2, '.'));
    let (payload, header) = expect_two!(message.rsplitn(2, '.'));
    let header = Header::from_encoded(header)?;

    if validation.validate_signature && !validation.algorithms.contains(&header.alg) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    if validation.validate_signature && header.alg.family() == AlgorithmFamily::Acl {
        return Err(new_error(ErrorKind::InvalidSignature));
    }

    if validation.validate_signature
        && header.alg.family() != AlgorithmFamily::Acl
        && !verify(signature, message.as_bytes(), key, header.alg)?
    {
        return Err(new_error(ErrorKind::InvalidSignature));
    }

    Ok((header, payload))
}

// K should satisfy that K1 = K2 iff K1.to_str() == K2.to_str()
pub fn decode_acl_selective_disclosure<K: ToString + Hash, V: FromStr + Hash + Clone>(
    token: &str,
    attribute_keys: &[K],
    params: &UserParameters,
) -> Result<TokenData<Vec<(K, V)>>> {
    // TODO: at some point, we should support the "validation" struct

    let now = Instant::now();

    let (signature, message) = expect_two!(token.rsplitn(2, '.'));
    let (raw_payload, header) = expect_two!(message.rsplitn(2, '.'));
    let header = Header::from_encoded(header)?;

    // step 1 is to verify the ACL signature
    let sig: Signature = bincode::deserialize(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();

    let payload: AclPayload =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&raw_payload).unwrap()).unwrap();

    let blinded_commitment = CompressedRistretto::from_slice(
        &URL_SAFE_NO_PAD.decode(payload.blinded_commitment).unwrap(),
    )
    .unwrap()
    .decompress()
    .unwrap();

    let verify_result = params.key.verify_prehashed(&[0u8; 64], &blinded_commitment, &sig);

    if verify_result.is_err() {
        return Err(new_error(ErrorKind::InvalidSignature));
    }

    // step 2 is to verify the dleq proof

    let disclosed_keys: Vec<String> =
        payload.disclosed_claims.clone().into_iter().map(|(k, _v)| k).collect();

    let attribute_keys_as_strs: Vec<String> =
        attribute_keys.into_iter().map(|k| k.to_string()).collect();

    for key in &disclosed_keys {
        if !attribute_keys_as_strs.contains(&key) {
            return Err(new_error(ErrorKind::InvalidSignature));
        }
    }

    let decoded_dleq_proof: Vec<Scalar> = payload
        .dleq_proof
        .into_iter()
        .map(|encoded_scalar| {
            Scalar::from_canonical_bytes(
                URL_SAFE_NO_PAD.decode(&encoded_scalar).unwrap().as_slice().try_into().unwrap(),
            )
            .unwrap()
        })
        .collect();

    let disclosed_generators: Vec<RistrettoPoint> =
        disclosed_keys.clone().into_iter().map(|k| key_to_generator(b"claim", k)).collect();

    let disclosed_blinded_generators: Vec<RistrettoPoint> = payload
        .disclosed_blinded_generators
        .into_iter()
        .map(|encoded_point| {
            CompressedRistretto::from_slice(&URL_SAFE_NO_PAD.decode(&encoded_point).unwrap())
                .unwrap()
                .decompress()
                .unwrap()
        })
        .collect();

    let generators: Vec<RistrettoPoint> =
        vec![disclosed_generators, Vec::from([gen_z().clone()])].concat();

    println!("{:?}", generators.len());

    let statement: Vec<RistrettoPoint> =
        vec![disclosed_blinded_generators.clone(), Vec::from([sig.xi.clone()])].concat();

    let dleq_result = verify_dleq(&generators, &statement, &decoded_dleq_proof);

    if dleq_result.is_err() {
        return Err(new_error(ErrorKind::InvalidSignature));
    }

    // last is to verify the representation proof

    let undisclosed_generators: Vec<RistrettoPoint> = attribute_keys
        .into_iter()
        .filter(|k| !disclosed_keys.contains(&k.to_string()))
        .map(|k| key_to_generator(b"claim", k))
        .collect();

    let mut Cminus: RistrettoPoint = blinded_commitment;

    for (i, (_k, v)) in payload.disclosed_claims.into_iter().enumerate() {
        Cminus = Cminus - disclosed_blinded_generators[i] * value_to_scalar(b"", v);
    }

    let decoded_repr_proof: Vec<Scalar> = payload
        .repr_proof
        .into_iter()
        .map(|encoded_scalar| {
            Scalar::from_canonical_bytes(
                URL_SAFE_NO_PAD.decode(&encoded_scalar).unwrap().as_slice().try_into().unwrap(),
            )
            .unwrap()
        })
        .collect();

    let repr_result =
        verify_linear(&vec![undisclosed_generators.clone(), Vec::from([RistrettoPoint::mul_base(&Scalar::from(1 as u32)), gen_h0().clone()])].concat(), &Vec::from([Cminus]), &decoded_repr_proof);

    if repr_result.is_err() {
        return Err(new_error(ErrorKind::InvalidSignature));
    }

    println!("verification took: {:?}", now.elapsed());

    Ok(TokenData { header: header, claims: Vec::new() })
}

/// Decode and validate a JWT
///
/// If the token or its signature is invalid or the claims fail validation, it will return an error.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let token = "a.jwt.token".to_string();
/// // Claims is a struct that implements Deserialize
/// let token_message = decode::<Claims>(&token, &DecodingKey::from_secret("secret".as_ref()), &Validation::new(Algorithm::HS256));
/// ```
pub fn decode<T: DeserializeOwned>(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<T>> {
    match verify_signature(token, key, validation) {
        Err(e) => Err(e),
        Ok((header, claims)) => {
            let decoded_claims = DecodedJwtPartClaims::from_jwt_part_claims(claims)?;
            let claims = decoded_claims.deserialize()?;
            validate(decoded_claims.deserialize()?, validation)?;

            Ok(TokenData { header, claims })
        }
    }
}

/// Decode a JWT without any signature verification/validations and return its [Header](struct.Header.html).
///
/// If the token has an invalid format (ie 3 parts separated by a `.`), it will return an error.
///
/// ```rust
/// use jsonwebtoken::decode_header;
///
/// let token = "a.jwt.token".to_string();
/// let header = decode_header(&token);
/// ```
pub fn decode_header(token: &str) -> Result<Header> {
    let (_, message) = expect_two!(token.rsplitn(2, '.'));
    let (_, header) = expect_two!(message.rsplitn(2, '.'));
    Header::from_encoded(header)
}
