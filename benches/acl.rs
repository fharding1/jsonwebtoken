use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jsonwebtoken::{SignatureProvider,get_acl_pretoken_full_disclosure,Algorithm,Header,encode_acl};
use acl::{SigningKey,SignerState,VerifyingKey,UserParameters,SECRET_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use curve25519_dalek::ristretto::RistrettoPoint;
use serde_json::{Value,json};

#[derive(Debug)]
pub struct LocalPVD {
    key: SigningKey,
    state: Option<SignerState>,
}

pub fn new_local_pvd(sk: SigningKey) -> LocalPVD {
    LocalPVD { key: sk, state: None }
}

impl SignatureProvider for LocalPVD {
    type Error = Box<dyn std::error::Error>;

    fn prepare(
        &mut self,
        commitment: &RistrettoPoint,
        _aux: String,
    ) -> std::result::Result<Vec<u8>, Self::Error> {
        let (ss, output) = self.key.prepare(commitment).expect("todo");
        self.state = Some(ss);

        Ok(output)
    }

    fn compute_presignature(
        &mut self,
        challenge_bytes: &[u8],
    ) -> std::result::Result<Vec<u8>, Self::Error> {
        if let Some(state) = &self.state {
            let sig = self.key.compute_presignature(&state, challenge_bytes).expect("todo");
            return Ok(sig);
        }

        panic!("this shouldn't happen");
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct TokenData {
    email: String,
    exp: u64,
    tech_subscriber: bool,
    sports_subscriber: bool,
    cooking_subscriber: bool,
}

impl TokenData {
    fn to_claims(&self) -> Value {
        json!({
            "cooking_subscriber": self.cooking_subscriber,
            "email": self.email,
            "exp": self.exp as u32,
            "sports_subscriber": self.sports_subscriber,
            "tech_subscriber": self.tech_subscriber,
        })
    }
}


fn bench_get_acl_pretoken_full_disclosure(c: &mut Criterion) {
    let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
        157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068, 073,
        197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
    ];

    let signing_key: SigningKey = SigningKey::from_bytes(&secret_key_bytes);

    let mut localPVD = new_local_pvd(signing_key);

    let user_params = UserParameters { key: VerifyingKey::from(&signing_key) };

    let tkd = &TokenData{
        email: "fharding1@protonmail.com".to_string(),
        exp: 1733255063,
        tech_subscriber: true,
        sports_subscriber: true,
        cooking_subscriber: true,
    };

    c.bench_function("bench_get_acl_pretoken_full_disclosure", |b| {
        b.iter(|| {
            let token = black_box(get_acl_pretoken_full_disclosure(black_box(&tkd.to_claims()), black_box(&mut localPVD), black_box(&user_params)).expect("OK"));
        });
    });
}

fn bench_encode_acl(c: &mut Criterion) {
    let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
        157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068, 073,
        197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
    ];

    let signing_key: SigningKey = SigningKey::from_bytes(&secret_key_bytes);

    let mut localPVD = new_local_pvd(signing_key);

    let user_params = UserParameters { key: VerifyingKey::from(&signing_key) };

    let tkd = &TokenData{
        email: "fharding1@protonmail.com".to_string(),
        exp: 1733255063,
        tech_subscriber: true,
        sports_subscriber: true,
        cooking_subscriber: true,
    };

    let pretoken = get_acl_pretoken_full_disclosure(black_box(&tkd.to_claims()), black_box(&mut localPVD), black_box(&user_params)).expect("OK");

    c.bench_function("bench_encode_acl", |b| {
        b.iter(|| {
            let token = black_box(encode_acl(
                black_box(&Header::new(Algorithm::AclFullPartialR255)),
                black_box(&tkd.to_claims()),
                black_box(&Vec::from(["exp".to_string(), "tech_subscriber".to_string()])),
                black_box(&pretoken),
            ));
        });
    });
}

criterion_group!(benches, bench_encode_acl, bench_get_acl_pretoken_full_disclosure);
criterion_main!(benches);
