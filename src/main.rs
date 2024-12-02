use num_bigint::BigUint;
use rand::Rng;
use sha2::{Sha256, Digest};

fn generate_keypair(p: &BigUint, g: &BigUint) -> (BigUint, BigUint) {
    let private_key = BigUint::from(rand::thread_rng().gen_range(1u32..23u32)); // x
    let public_key = g.modpow(&private_key, &p); // y = g^x mod p

    (private_key, public_key)
}

fn prover_commit(p: &BigUint, g: &BigUint) -> (BigUint, BigUint) {
    generate_keypair(p, g)
}

fn generate_challenge(g: &BigUint, p: &BigUint, y: &BigUint, t: &BigUint) -> BigUint {
    let params = format!("{}{}{}{}", g, p, y, t);
    
    let mut hasher = Sha256::new();
    hasher.update(params.as_bytes());
    let result = hasher.finalize();
    
    BigUint::from_bytes_be(&result[0..4])
}

fn prover_response(r: &BigUint, e: &BigUint, private_key: &BigUint, q: &BigUint) -> BigUint {
    (r + e * private_key) % q
}

fn verifier_verification(g: &BigUint, s: &BigUint, p: &BigUint, t: &BigUint, public_key: &BigUint, e: &BigUint) -> bool {
    // g^s mod p == t * y^e mod p
    
    let l = g.modpow(s, p);
    let r = (t * public_key.modpow(e, p)) % p;

    l == r
}

fn main() {
    // Schnorr Protocol

    // Prover wants to convince the Verifier that he knows x without revealing it

    // 0. Setup

    // p, q and g are public cryptographic parameters

    // x is private

    // Prover computes y = g^x mod p

    // Prover shares y

    let p = BigUint::from(23u32);
    let q = BigUint::from(11u32);
    let g = BigUint::from(4u32);
    
    println!("p: {}", &p);
    println!("q: {}", &q);
    println!("g: {}", &g);

    let (x, y) = generate_keypair(&p, &g);

    println!("x: {}", &x);
    println!("y: {}", &y);

    // 1. Commitment

    // Prover chooses a random r

    // Prover computes t = g^r mod p

    // Prover shares t

    let (r, t) = prover_commit(&p, &g);

    println!("r: {}", &r);
    println!("t: {}", &t);

    // 2. Challenge

    // Instead of verifier choosing random e, prover generates it deterministically
    let e = generate_challenge(&g, &p, &y, &t);

    println!("e: {}", &e);

    // 3. Response

    // Prover computes s = r + e * x mod p

    // Prover shares s

    let s = prover_response(&r, &e, &x, &q);

    println!("s: {}", &s);

    // 4. Verification

    // Verifier computes g^s mod p = t * y^e mod p

    let ok = verifier_verification(&g, &s, &p, &t, &y, &e);

    println!("ok: {}", &ok);
}
