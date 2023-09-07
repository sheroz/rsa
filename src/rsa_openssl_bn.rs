#[cfg(test)]
mod tests {

    #[test]
    fn sample_rsa_openssl_bn() {
        use openssl::bn::{BigNum, BigNumContext};

        struct PublicKey {
            e: BigNum,
            n: BigNum,
        }

        struct PrivateKey {
            d: BigNum,
            n: BigNum,
        }

        let mut ctx = BigNumContext::new().unwrap();

        // 1. Choose two distinct primes p and q
        let p = BigNum::from_u32(3).unwrap();
        let q = BigNum::from_u32(11).unwrap();

        // 2. Compute the modulus, n = pq
        let n = &p * &q;
        assert_eq!(n, BigNum::from_u32(33).unwrap());

        // 3. Compute the totient, t
        // there is no lcm() in openssl (!!!)
        // https://crypto.stackexchange.com/questions/94926/rsa-private-exponent-generation-according-to-fips-186-4-in-openssl-v1
        // openssl uses Euler's totient function
        // t = (p − 1) * (q − 1)
        let one = BigNum::from_u32(1).unwrap();
        let mut p1 = BigNum::new().unwrap();
        p1.checked_sub(&p, &one).unwrap();
        let mut q1 = BigNum::new().unwrap();
        q1.checked_sub(&q, &one).unwrap();
        let t = &p1 * &q1;
        assert_eq!(t, BigNum::from_u32(20).unwrap());

        // 4. Choose any number 1 < e < t that is coprime to t
        // Choosing a prime number for e leaves us only to check that e is not a divisor of t
        let e =  BigNum::from_u32(7).unwrap();
        let mut gcd = BigNum::new().unwrap();
        gcd.gcd(&e, &t, &mut ctx).unwrap();
        assert_eq!(gcd, BigNum::from_u32(1).unwrap());

        // 5. Compute d
        let mut d = BigNum::new().unwrap();
        d.mod_inverse(&e, &t, &mut ctx).unwrap();
        assert_eq!(d, BigNum::from_u32(3).unwrap());

        let n_slice = n.to_vec();

        // 6. public key is (e = 7, n = 33)
        let public_key = PublicKey { e, n: BigNum::from_slice(&n_slice).unwrap()};

        // 7. private key is (d = 3, n = 33)
        let private_key = PrivateKey { d, n: BigNum::from_slice(&n_slice).unwrap() };

        // message, m = 2
        let m = BigNum::from_u32(2).unwrap();

        // 8. encryption
        // c = (m ^ e) mod n
        let mut c = BigNum::new().unwrap();
        c.mod_exp(&m, &public_key.e, &public_key.n, &mut ctx).unwrap();
        assert_eq!(c.to_string(), "29");

        // 9. decryption
        // D = (c ^ d) mod n
        let mut dm = BigNum::new().unwrap();
        dm.mod_exp(&c, &private_key.d, &private_key.n, &mut ctx).unwrap();
        assert_eq!(dm.to_string(), "2");

        assert_eq!(m, dm);
    }
}
