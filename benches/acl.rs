use criterion::{black_box, criterion_group, criterion_main, Criterion,BenchmarkId};
use jsonwebtoken::{SignatureProvider,get_acl_pretoken_full_disclosure,Algorithm,Header,encode_acl};
use acl::{SigningKey,SignerState,VerifyingKey,UserParameters,SECRET_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use curve25519_dalek::ristretto::RistrettoPoint;
use serde_json::{Value,json,Map};

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
struct TokenData {}

impl TokenData {
    fn to_claims(&self, n: u32) -> Value {
        let mut v = Map::new();
        for i in 0..n {
            v.insert(i.to_string(), Value::String(i.to_string()));
        }
        Value::Object(v)
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

    let tkd = &TokenData{};

    let mut group = c.benchmark_group("bench_get_acl_pretoken_full_disclosure");
    for n in (0..11).map(|v| 1 << v) {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let token = black_box(get_acl_pretoken_full_disclosure(black_box(&tkd.to_claims(n)), black_box(&mut localPVD), black_box(&user_params)).expect("OK"));
            });
        });
    }
    group.finish();
}

fn bench_encode_acl(c: &mut Criterion) {
    let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
        157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068, 073,
        197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
    ];

    let signing_key: SigningKey = SigningKey::from_bytes(&secret_key_bytes);

    let mut localPVD = new_local_pvd(signing_key);

    let user_params = UserParameters { key: VerifyingKey::from(&signing_key) };

    let tkd = &TokenData{};


    let mut group = c.benchmark_group("bench_encode_acl");
    for n in (0..5).map(|v| 1 << v*2) {
        for d in [&Vec::from([0 as u32])[..], &Vec::from((0..11).map(|v| 1 << v).collect::<Vec<u32>>())[..]].concat() {
            if d > n {
                continue
            }

    let mut disclose: Vec<String> = (1..d+1).map(|v| v.to_string()).collect();
    if d == 0 {
        disclose = Vec::new()
    }

    let pretoken = get_acl_pretoken_full_disclosure(black_box(&tkd.to_claims(n)), black_box(&mut localPVD), black_box(&user_params)).expect("OK");
        group.bench_with_input(BenchmarkId::from_parameter(format!("{}/{}", d,n)), &(n,d), |b, &(n,d)| {
            b.iter(|| {
                let token = black_box(encode_acl(
                    black_box(&Header::new(Algorithm::AclFullPartialR255)),
                    black_box(&tkd.to_claims(n)),
                    black_box(&disclose),
                    black_box(&pretoken),
            ));
        });
    });
        }
    }
}

criterion_group!(benches, bench_encode_acl, bench_get_acl_pretoken_full_disclosure);
criterion_main!(benches);
