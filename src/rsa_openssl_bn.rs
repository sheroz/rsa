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
        let p = BigNum::from_u32(653).unwrap();
        let q = BigNum::from_u32(877).unwrap();

        // 2. Compute the modulus, n = p*q
        let n = &p * &q;
        assert_eq!(n, BigNum::from_u32(572681).unwrap());

        // 3. Compute the totient, t
        // there is no lcm() in openssl (!!!)
        // https://crypto.stackexchange.com/questions/94926/rsa-private-exponent-generation-according-to-fips-186-4-in-openssl-v1
        // openssl uses Euler's totient function
        // t = (p − 1) * (q − 1)
        let one = BigNum::from_u32(1).unwrap();
        let mut p_1 = BigNum::new().unwrap();
        p_1.checked_sub(&p, &one).unwrap();
        let mut q_1 = BigNum::new().unwrap();
        q_1.checked_sub(&q, &one).unwrap();
        let t = &p_1 * &q_1;
        assert_eq!(t, BigNum::from_u32(571152).unwrap());

        // 4. Choose any number 1 < e < t that is coprime to t
        // Choosing a prime number for e leaves us only to check that e is not a divisor of t
        let e =  BigNum::from_u32(13).unwrap();
        let mut gcd = BigNum::new().unwrap();
        gcd.gcd(&e, &t, &mut ctx).unwrap();
        assert_eq!(gcd, BigNum::from_u32(1).unwrap());

        // 5. Compute d
        let mut d = BigNum::new().unwrap();
        d.mod_inverse(&e, &t, &mut ctx).unwrap();
        assert_eq!(d, BigNum::from_u32(395413).unwrap());

        let n_slice = n.to_vec();

        // 6. public key is (e, n)
        let public_key = PublicKey { e, n: BigNum::from_slice(&n_slice).unwrap()};

        // 7. private key is (d, n)
        let private_key = PrivateKey { d, n: BigNum::from_slice(&n_slice).unwrap() };

        // message, m
        let m = BigNum::from_u32(12345).unwrap();

        // encryption
        // c = (m ^ e) mod n
        let mut c = BigNum::new().unwrap();
        c.mod_exp(&m, &public_key.e, &public_key.n, &mut ctx).unwrap();
        assert_eq!(c.to_string(), "536754");

        // decryption
        // D = (c ^ d) mod n
        let mut dm = BigNum::new().unwrap();
        dm.mod_exp(&c, &private_key.d, &private_key.n, &mut ctx).unwrap();
        assert_eq!(dm.to_string(), "12345");

        assert_eq!(m, dm);
    }
}
