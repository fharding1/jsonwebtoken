use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

use crate::algorithms::{Algorithm, AlgorithmFamily};
use crate::crypto;
use crate::errors::{new_error, ErrorKind, Result};
use crate::header::Header;
#[cfg(feature = "use_pem")]
use crate::pem::decoder::PemEncodedKey;
use crate::serialization::b64_encode_part;
use acl::{gen_z, Signature, SignerState, SigningKey, UserParameters};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use okamoto::{prove_dleq, prove_linear};
use std::fmt::Debug;

use rand_core::OsRng;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::string::ToString;
use std::sync::OnceLock;

/// A key to encode a JWT with. Can be a secret, a PEM-encoded key or a DER-encoded key.
/// This key can be re-used so make sure you only initialize it once if you can for better performance.
#[derive(Clone)]
pub struct EncodingKey {
    pub(crate) family: AlgorithmFamily,
    content: Vec<u8>,
}

impl EncodingKey {
    /// If you're using a HMAC secret that is not base64, use that.
    pub fn from_secret(secret: &[u8]) -> Self {
        EncodingKey { family: AlgorithmFamily::Hmac, content: secret.to_vec() }
    }

    /// If you have a base64 HMAC secret, use that.
    pub fn from_base64_secret(secret: &str) -> Result<Self> {
        let out = STANDARD.decode(secret)?;
        Ok(EncodingKey { family: AlgorithmFamily::Hmac, content: out })
    }

    /// If you are loading a RSA key from a .pem file.
    /// This errors if the key is not a valid RSA key.
    /// Only exists if the feature `use_pem` is enabled.
    ///
    /// # NOTE
    ///
    /// According to the [ring doc](https://docs.rs/ring/latest/ring/signature/struct.RsaKeyPair.html#method.from_pkcs8),
    /// the key should be at least 2047 bits.
    ///
    #[cfg(feature = "use_pem")]
    pub fn from_rsa_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_rsa_key()?;
        Ok(EncodingKey { family: AlgorithmFamily::Rsa, content: content.to_vec() })
    }

    /// If you are loading a ECDSA key from a .pem file
    /// This errors if the key is not a valid private EC key
    /// Only exists if the feature `use_pem` is enabled.
    ///
    /// # NOTE
    ///
    /// The key should be in PKCS#8 form.
    ///
    /// You can generate a key with the following:
    ///
    /// ```sh
    /// openssl ecparam -genkey -noout -name prime256v1 \
    ///     | openssl pkcs8 -topk8 -nocrypt -out ec-private.pem
    /// ```
    #[cfg(feature = "use_pem")]
    pub fn from_ec_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ec_private_key()?;
        Ok(EncodingKey { family: AlgorithmFamily::Ec, content: content.to_vec() })
    }

    /// If you are loading a EdDSA key from a .pem file
    /// This errors if the key is not a valid private Ed key
    /// Only exists if the feature `use_pem` is enabled.
    #[cfg(feature = "use_pem")]
    pub fn from_ed_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ed_private_key()?;
        Ok(EncodingKey { family: AlgorithmFamily::Ed, content: content.to_vec() })
    }

    /// If you know what you're doing and have the DER-encoded key, for RSA only
    pub fn from_rsa_der(der: &[u8]) -> Self {
        EncodingKey { family: AlgorithmFamily::Rsa, content: der.to_vec() }
    }

    /// If you know what you're doing and have the DER-encoded key, for ECDSA
    pub fn from_ec_der(der: &[u8]) -> Self {
        EncodingKey { family: AlgorithmFamily::Ec, content: der.to_vec() }
    }

    /// If you know what you're doing and have the DER-encoded key, for EdDSA
    pub fn from_ed_der(der: &[u8]) -> Self {
        EncodingKey { family: AlgorithmFamily::Ed, content: der.to_vec() }
    }

    pub(crate) fn inner(&self) -> &[u8] {
        &self.content
    }
}

/// Encode the header and claims given and sign the payload using the algorithm from the header and the key.
/// If the algorithm given is RSA or EC, the key needs to be in the PEM format.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken::{encode, Algorithm, Header, EncodingKey};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let my_claims = Claims {
///     sub: "b@b.com".to_owned(),
///     company: "ACME".to_owned()
/// };
///
/// // my_claims is a struct that implements Serialize
/// // This will create a JWT using HS256 as algorithm
/// let token = encode(&Header::default(), &my_claims, &EncodingKey::from_secret("secret".as_ref())).unwrap();
/// ```
pub fn encode<T: Serialize>(header: &Header, claims: &T, key: &EncodingKey) -> Result<String> {
    if key.family != header.alg.family()
        || header.alg.family() == AlgorithmFamily::Acl
        || key.family == AlgorithmFamily::Acl
    {
        // TODO: should have two kinds of errors here prolly
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }
    let encoded_header = b64_encode_part(header)?;
    let encoded_claims = b64_encode_part(claims)?;
    let message = [encoded_header, encoded_claims].join(".");
    let signature = crypto::sign(message.as_bytes(), key, header.alg)?;

    Ok([message, signature].join("."))
}

pub trait SignatureProvider {
    type Error;

    fn prepare(
        &mut self,
        commitment: &RistrettoPoint,
        aux: String,
    ) -> std::result::Result<Vec<u8>, Self::Error>;
    fn compute_presignature(
        &mut self,
        challenge_bytes: &[u8],
    ) -> std::result::Result<Vec<u8>, Self::Error>;
}

#[derive(Debug)]
pub struct LocalPVD {
    key: SigningKey,
    state: Option<SignerState>,
}

pub fn new_local_pvd(sk: SigningKey) -> LocalPVD {
    LocalPVD { key: sk, state: None }
}

impl SignatureProvider for LocalPVD {
    type Error = crate::errors::Error;

    fn prepare(
        &mut self,
        commitment: &RistrettoPoint,
        _aux: String,
    ) -> std::result::Result<Vec<u8>, crate::errors::Error> {
        let (ss, output) = self.key.prepare(commitment).expect("todo");
        self.state = Some(ss);

        Ok(output)
    }

    fn compute_presignature(
        &mut self,
        challenge_bytes: &[u8],
    ) -> std::result::Result<Vec<u8>, crate::errors::Error> {
        if let Some(state) = &self.state {
            let sig = self.key.compute_presignature(&state, challenge_bytes).expect("todo");
            return Ok(sig);
        }

        Err(new_error(ErrorKind::ExpiredSignature)) // todo: this is totally wrong
    }
}

pub fn key_to_generator<K: Hash>(prefix: &[u8], key: K) -> RistrettoPoint {
    let mut hasher = DefaultHasher::new();
    prefix.hash(&mut hasher);
    key.hash(&mut hasher);
    let result = hasher.finish();
    RistrettoPoint::mul_base(&Scalar::from(result))
}

pub fn value_to_scalar<V: Hash>(prefix: &[u8], value: V) -> Scalar {
    let mut hasher = DefaultHasher::new();
    prefix.hash(&mut hasher);
    value.hash(&mut hasher);
    let result = hasher.finish();
    Scalar::from(result)
}

// nothing-up-my-sleeve generation of blinding generator as H0=Hash("H0")
pub fn gen_h0() -> &'static RistrettoPoint {
    static GENERATOR_H: OnceLock<RistrettoPoint> = OnceLock::new();
    GENERATOR_H.get_or_init(|| key_to_generator(b"", "H0"))
}

#[derive(serde::Serialize, Deserialize, Debug)]
pub struct AclPayload {
    blinded_commitment: String,
    disclosed_claims: Vec<(String, String)>,
    disclosed_blinded_generators: Vec<String>,
    dleq_proof: Vec<String>,
    repr_proof: Vec<String>,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct PreToken {
    pub sig: Signature,
    pub blinded_commitment: RistrettoPoint,
    pub randomness: Scalar,
    pub gamma: Scalar,
    pub rnd: Scalar,
}

pub fn get_acl_pretoken_full_disclosure<
    K: Eq + Hash + ToString + Clone,
    V: Hash + Clone + ToString,
    S: SignatureProvider,
>(
    claims: &[(K, V)],
    pvd: &mut S,
    params: &UserParameters,
) -> Result<PreToken>
where
    S::Error: Debug,
{
    let randomness = Scalar::random(&mut OsRng);
    let commitment = gen_h0() * randomness
        + claims
            .into_iter()
            .map(|(k, v)| key_to_generator(b"claim", k) * value_to_scalar(b"", v))
            .sum::<RistrettoPoint>();

    // todo: actually do full disclosure
    let aux: String = "".to_string();

    let smsg = pvd.prepare(&commitment, aux).expect("asdf");
    println!("{:?}", smsg);
    let (st, umsg) =
        params.compute_challenge(&mut OsRng, &commitment, &[0u8; 64], &smsg).expect("asdf");
    let psig = pvd.compute_presignature(&umsg).expect("asdf");
    let (sig, blinded_commitment, gamma, rnd) = params.compute_signature(&st, &psig).expect("asdf");

    Ok(PreToken { sig, blinded_commitment, randomness, gamma, rnd })
}

pub fn encode_acl<
    K: Eq + Hash + ToString + Clone,
    V: Hash + Clone + ToString,
>(
    header: &Header,
    claims: &[(K, V)],
    disclose: &[K],
    pretoken: &PreToken,
) -> Result<String>
{
    // TODO: encode disclosed claims and add proof for selective disclosure
    let encoded_header = b64_encode_part(header)?;

    let disclosed_claims: Vec<(String, String)> = claims
        .iter()
        .filter(|(k, v)| disclose.contains(k))
        .cloned()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let mut disclosed_generators: Vec<RistrettoPoint> = Vec::new();
    let mut disclosed_blinded_generators: Vec<RistrettoPoint> = Vec::new();
    let mut undisclosed_generators: Vec<RistrettoPoint> = Vec::new();
    let mut Cminus = pretoken.blinded_commitment;
    let mut undisclosed_attribute_witnesses: Vec<Scalar> = Vec::new();

    for (i, (k, v)) in claims.into_iter().enumerate() {
        let generator = key_to_generator(b"claim", k);
        if disclose.contains(k) {
            disclosed_generators.push(generator);
            disclosed_blinded_generators.push(pretoken.gamma * generator);
            Cminus = Cminus - value_to_scalar(b"", v) * pretoken.gamma * generator;
        } else {
            undisclosed_generators.push(generator);
            undisclosed_attribute_witnesses.push(pretoken.gamma * value_to_scalar(b"", v));
        }
    }

    let dleq_proof = &prove_dleq(
        &vec![disclosed_generators, Vec::from([gen_z().clone()])].concat(),
        &pretoken.gamma,
        &vec![disclosed_blinded_generators.clone(), Vec::from([pretoken.gamma * gen_z()])].concat(),
    )
    .expect("asdf");

    undisclosed_generators.push(RistrettoPoint::mul_base(&Scalar::from(1 as u32)));
    undisclosed_attribute_witnesses.push(pretoken.gamma * pretoken.rnd);
    undisclosed_generators.push(gen_h0().clone());
    undisclosed_attribute_witnesses.push(pretoken.gamma * pretoken.randomness);

    let repr_proof = prove_linear(
        &undisclosed_generators,
        &undisclosed_attribute_witnesses,
        &Vec::from([Cminus]),
    )
    .expect("asdfasdf");

    let encoded_claims = b64_encode_part(&AclPayload {
        blinded_commitment: URL_SAFE_NO_PAD.encode(pretoken.blinded_commitment.compress().as_bytes()),
        disclosed_claims: disclosed_claims,
        disclosed_blinded_generators: disclosed_blinded_generators
            .into_iter()
            .map(|p| URL_SAFE_NO_PAD.encode(p.compress().as_bytes()))
            .collect(),
        dleq_proof: dleq_proof.into_iter().map(|s| URL_SAFE_NO_PAD.encode(s.as_bytes())).collect(),
        repr_proof: repr_proof.into_iter().map(|s| URL_SAFE_NO_PAD.encode(s.as_bytes())).collect(),
    })?;

    let sig = URL_SAFE_NO_PAD.encode(&bincode::serialize(&pretoken.sig).unwrap());

    Ok([encoded_header, encoded_claims, sig].join("."))
}
