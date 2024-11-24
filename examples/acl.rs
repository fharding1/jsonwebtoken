use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::prelude::*;
use chrono::TimeDelta;
use jsonwebtoken::{
    decode, encode, encode_acl, get_current_timestamp, new_local_pvd, Algorithm, DecodingKey,
    EncodingKey, Header, Validation,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};

use acl::{SigningKey, UserParameters, VerifyingKey, SECRET_KEY_LENGTH};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand_core::OsRng;

use sha2::Sha512;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    test: String,
    exp: u64,
}

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
enum UserType {
    Free = 1,
    Subscriber = 2,
    Administrator = 64,
}

struct UserAttributes {
    user_id: u128,
    user_type: UserType,
}

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
enum UserAttributeID {
    UserID = 1,
    Type = 2,
}

impl UserAttributeID {
    fn as_bytes(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0] = *self as u8;
        buf
    }
}

fn main() {
    let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
        157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068, 073,
        197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
    ];

    let signing_key: SigningKey = SigningKey::from_bytes(&secret_key_bytes);

    /*
    let bob = UserAttributes { user_id: 1, user_type: UserType::Subscriber };

    let attribute_ids = [UserAttributeID::UserID.as_bytes(), UserAttributeID::Type.as_bytes()];

    let commitment = RistrettoPoint::mul_base(&Scalar::from(1 as u32));
    //let commitment = commit(&mut OsRng, attribute_ids, [bob.user_id, bob.user_type as u128]);

    println!("commitment : {:?}", commitment);

    let (ss, prepare_message) = signing_key.prepare(&commitment).expect("this should work");

    let user_params =
        UserParameters { key: VerifyingKey::from(&signing_key) };

    let (us, challenge) = user_params
        .compute_challenge(&mut OsRng, &commitment, &[0u8; 64], &prepare_message)
        .expect("this should work");

    let presignature = signing_key.compute_presignature(&ss, &challenge).expect("should work");

    let (signature, blinded_commitment, gamma, rnd) =
        user_params.compute_signature(&us, &presignature).expect("sig should be fine");

    println!(
        "valid: {:?}",
        user_params.key.verify_prehashed(&[0u8; 64], &blinded_commitment, &signature)
    );
    println!(
        "valid: {:?}",
        user_params.key.verify_prehashed(&[1u8; 64], &blinded_commitment, &signature)
    );
    */

    let signing_key: SigningKey = SigningKey::from_bytes(&secret_key_bytes);

    let mut localPVD = new_local_pvd(signing_key);

    println!("{:?}", localPVD);

    let user_params = UserParameters { key: VerifyingKey::from(&signing_key) };

    let now = Utc::now();
    let exp =
        Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0).latest().expect("fine")
            + TimeDelta::days(1);
    let claims = Claims { test: String::from("Hello, World!"), exp: exp.timestamp() as u64 };

    let token = encode_acl(
        &Header::new(Algorithm::AclFullPartialR255),
        &Vec::from([("exp".to_string(), (exp.timestamp() as u64))]),
        &Vec::from(["exp".to_string()]),
        &mut localPVD,
        &user_params,
    )
    .unwrap();

    println!("token: {:?}", token);

    /*

    let decoding_key = DecodingKey::from_acl_vk(VerifyingKey::from(&signing_key));

    let validation = Validation::new(Algorithm::AclR255);
    let token_data = decode::<Claims>(&token, &decoding_key, &validation);

    println!("{:?}", token_data);

    /*

    let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let encoding_key = EncodingKey::from_ed_der(doc.as_ref());

    let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
    let decoding_key = DecodingKey::from_ed_der(pair.public_key().as_ref());

    let claims = Claims { sub: "test".to_string(), exp: get_current_timestamp() };

    let token =
        encode(&jsonwebtoken::Header::new(Algorithm::EdDSA), &claims, &encoding_key).unwrap();

    let validation = Validation::new(Algorithm::EdDSA);
    let _token_data = decode::<Claims>(&token, &decoding_key, &validation).unwrap();

    */
    */
}
