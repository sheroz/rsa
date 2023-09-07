#[cfg(test)]
mod tests {

    #[test]
    fn wiki_sample_rsa_num() {
        use num_bigint::BigInt;
        use num_integer;

        struct PublicKey {
            e: u32,
            n: BigInt,
        }

        struct PrivateKey {
            d: u32,
            n: BigInt,
        }

        // 1. Choose two distinct primes p and q
        let p = BigInt::from(61);
        let q = BigInt::from(53);

        // 2. Compute the modulus, n = pq
        // n = 61 * 53 = 3233
        let n = p.clone() * q.clone();
        assert_eq!(n, BigInt::from(3233));

        // 3. Compute the totient, t
        // λ(3233) = lcm(60, 52) = 780
        let t = num_integer::lcm(p - 1, q - 1);
        assert_eq!(t, BigInt::from(780));

        // 4. Choose any number 1 < e < t that is coprime to t
        // Choosing a prime number for e leaves us only to check that e is not a divisor of t
        let e = 17;
        assert_eq!(num_integer::gcd(BigInt::from(e), t), BigInt::from(1));

        // 5. Compute d
        // there is no modular multiplicative inverse function in num crate (!!!)
        // although, I see related discussions and submits, no such a function yet
        let d = 413;
        assert_eq!(d, 413);

        // 6. public key is (e = 17, n = 3233)
        let public_key = PublicKey { e, n: n.clone() };

        // 7. private key is (d = 413, n = 3233)
        let private_key = PrivateKey { d, n: n.clone() };

        // message, m = 65
        let m = BigInt::from(65);

        // 8. encryption
        // c = (m ^ e) mod n
        let c = m.pow(public_key.e) % public_key.n;
        assert_eq!(c.to_string(), "2790");

        // 9. decryption
        // D = (c ^ d) mod n
        let dm = c.pow(private_key.d) % private_key.n;
        assert_eq!(dm.to_string(), "65");

        assert_eq!(m, dm);
    }
}
