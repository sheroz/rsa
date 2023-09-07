// https://gitlab.com/tspiteri/rug       
// https://gmplib.org/ 

use rug::{Integer, Float, rand::RandState};

pub struct PublicKey {
    e: Integer,
    n: Integer,
}

pub struct PrivateKey {
    d: Integer,
    n: Integer,
}

/// Returns generated RSA keys
/// RSA key length is the length of the modulus n in bits
/// 
/// # Arguments
/// 
/// * `nlen` - the appropriate length in bits for the desired security strength
pub fn generate_keys(nlen: u16) -> (PublicKey, PrivateKey) {
    // Key generation
    // https://datatracker.ietf.org/doc/html/rfc2313#section-6

    // 1. Choose two distinct primes p and q
    let (p, q) = rsa_primes_p_q(nlen);

    // 2. Compute the modulus, n = p * q
    let n = p.clone() * q.clone();

    // 3. Compute the totient, t
    let p_1: Integer = p.clone() - 1;
    let q_1: Integer = q.clone() - 1;
    let t = p_1.lcm(&q_1);

    // 4. Choose any number 1 < e < t that is coprime to t
    // Choosing a prime number for e leaves us only to check that e is not a divisor of t
    let e =  Integer::from(65537);

    // 5. Compute d
    let d = e.clone().invert(&t).unwrap();

    // 6. public key is (e, n)
    let public_key = PublicKey { e, n: n.clone() };

    // 7. private key is (d, n)
    let private_key = PrivateKey { d, n: n.clone() };

    (public_key, private_key)
}

/// FIPS.186-4, Section: B.3.1 Criteria for IFC Key Pairs
/// 
/// sqrt(2)*2^((nlen/2)-1) <= p <= 2^(nlen/2)-1
/// 
/// sqrt(2)*2^((nlen/2)-1) <= q <= 2^(nlen/2)-1
/// 
/// |p - q| > 2^((nlen/2)-100)  
/// 
/// where nlen is the appropriate length for the desired security strength
fn rsa_primes_p_q(nlen: u16) -> (Integer, Integer){

    let mut rand_state = RandState::new();

    let fips_min = rsa_fips_key_constraint_min(nlen);
    let fips_max = rsa_fips_key_constraint_max(nlen);

    // compute fips_min <= p <= fips_max
    let boundary = fips_max.clone() - fips_min.clone();

    let p_random = fips_min.clone() + boundary.clone().random_below(&mut rand_state);
    let p = p_random.next_prime();

    // compute fips_min <= q <= fips_max
    let q_random = fips_min.clone() + boundary.clone().random_below(&mut rand_state);
    let q = q_random.next_prime();

    (p, q)
}

fn rsa_fips_key_constraint_min(nlen: u16) -> Integer {
    let float_precision = nlen as u32;
    let fips_min = Float::with_val(float_precision, 2).sqrt() * Float::with_val(float_precision, (nlen as u32/2)-1).exp2();
    fips_min.round().to_integer().unwrap()
}

fn rsa_fips_key_constraint_max(nlen: u16) -> Integer {
    let float_precision = nlen as u32;
    let fips_max: Float = Float::with_val(float_precision, nlen as u32/2).exp2() - 1;
    fips_max.round().to_integer().unwrap()
}

pub fn encrypt(m: Integer, public_key: &PublicKey) -> Integer {
    m.pow_mod(&public_key.e, &public_key.n).unwrap()
}

pub fn decrypt(c: Integer, private_key: &PrivateKey) -> Integer {
    c.pow_mod(&private_key.d, &private_key.n).unwrap()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn wiki_sample_rsa_gmp() {
        // 1. Choose two distinct primes p and q
        let p = Integer::from(61);
        let q = Integer::from(53);

        // 2. Compute the modulus, n = pq
        // n = 61 * 53 = 3233
        let n = p.clone() * q.clone();
        assert_eq!(n, 3233);

        // 3. Compute the totient, t
        // λ(3233) = lcm(60, 52) = 780
        let p1 = p.clone() - Integer::from(1);
        let q1 = q.clone() - Integer::from(1);
        let t = p1.lcm(&q1);
        assert_eq!(t, 780);

        // 4. Choose any number 1 < e < t that is coprime to t
        // Choosing a prime number for e leaves us only to check that e is not a divisor of t
        let e =  Integer::from(17);
        assert_eq!(e.clone().gcd(&t), 1);

        // 5. Compute d
        // 1 = (17 * 413) mod 780
        let d = e.clone().invert(&t).unwrap();
        assert_eq!(d, 413);

        // 6. public key is (e = 17, n = 3233)
        let public_key = PublicKey { e, n: n.clone() };

        // 7. private key is (d = 413, n = 3233)
        let private_key = PrivateKey { d, n: n.clone() };

        // message, m = 65
        let m = Integer::from(65);

        // 8. encryption
        // c = (m ^ e) mod n
        let c = m.clone().pow_mod(&public_key.e, &public_key.n).unwrap();
        assert_eq!(c, 2790);

        // 9. decryption
        // D = (c ^ d) mod n
        let dm = c.pow_mod(&private_key.d, &private_key.n).unwrap();
        assert_eq!(dm, 65);

        assert_eq!(m, dm);

    }

    #[test]
    fn rsa_primes_p_q_test() {

        let nlen = 16;
        let min = rsa_fips_key_constraint_min(nlen);
        let max = rsa_fips_key_constraint_max(nlen);
        assert_eq!(min, 181);
        assert_eq!(max, 255);

        let (p, q) = rsa_primes_p_q(nlen);
        assert_ne!(p, q);
        assert!(min <= p);
        assert!(p <= max);
        assert!(min <= q);
        assert!(q <= max);

        let nlen = 64;
        let min = rsa_fips_key_constraint_min(nlen);
        let max = rsa_fips_key_constraint_max(nlen);
        assert_eq!(min, 3037000500_u64);
        assert_eq!(max, 4294967295_u64);

        let (p, q) = rsa_primes_p_q(nlen);
        assert_ne!(p, q);
        assert!(min <= p);
        assert!(p <= max);
        assert!(min <= q);
        assert!(q <= max);

        let nlen = 1024;
        let min = rsa_fips_key_constraint_min(nlen);
        let max = rsa_fips_key_constraint_max(nlen);
        assert!(min.significant_bits() <= (nlen as u32 / 2));
        assert!(max.significant_bits() >= (nlen as u32 / 2));

        let (p, q) = rsa_primes_p_q(nlen);
        assert_ne!(p, q);
        assert!(min <= p);
        assert!(p <= max);
        assert!(min <= q);
        assert!(q <= max);

        let nlen = 2048;
        let min = rsa_fips_key_constraint_min(nlen);
        let max = rsa_fips_key_constraint_max(nlen);
        assert!(min.significant_bits() <= (nlen as u32 / 2));
        assert!(max.significant_bits() >= (nlen as u32 / 2));

        let (p, q) = rsa_primes_p_q(nlen);
        assert_ne!(p, q);
        assert!(min <= p);
        assert!(p <= max);
        assert!(min <= q);
        assert!(q <= max);

        let nlen = 4096;
        let min = rsa_fips_key_constraint_min(nlen);
        let max = rsa_fips_key_constraint_max(nlen);
        assert!(min.significant_bits() <= (nlen as u32 / 2));
        assert!(max.significant_bits() >= (nlen as u32 / 2));

        let (p, q) = rsa_primes_p_q(nlen);
        assert_ne!(p, q);
        assert!(min <= p);
        assert!(p <= max);
        assert!(min <= q);
        assert!(q <= max);

        // disabled to prevent delays in the continuous integration process
        /* 
        let nlen = 16384;
        let min = rsa_fips_key_constraint_min(nlen);
        let max = rsa_fips_key_constraint_max(nlen);
        assert!(min.significant_bits() <= (nlen as u32 / 2));
        assert!(max.significant_bits() >= (nlen as u32 / 2));

        let (p, q) = rsa_primes_p_q(nlen);
        assert_ne!(p, q);
        assert!(min <= p);
        assert!(p <= max);
        assert!(min <= q);
        assert!(q <= max);
        */
    }

    #[test]
    fn rsa_test() {
        let nlen = 2048;
        let (public_key, private_key) = generate_keys(nlen);

        // message, m = 65
        let m = Integer::from(12345);

        // encryption
        let c = encrypt(m.clone(), &public_key);
        assert!(c > 0);
        assert_ne!(m, c);

        // decryption
        let dm = decrypt(c.clone(), &private_key);
        assert_ne!(c, dm);

        assert_eq!(m, dm);
    }
}
