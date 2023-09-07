// RSA: https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture12.pdf
// https://blog.cloudflare.com/searching-for-the-prime-suspect-how-heartbleed-leaked-private-keys/
// https://www.lightbluetouchpaper.org/2014/04/25/heartbleed-and-rsa-private-keys/

// https://medium.com/snips-ai/prime-number-generation-2a02f28508ff
// https://github.com/AtropineTears/num-primes

use num::BigInt;
use openssl::bn::BigNum;
use rug::Integer;

pub struct PublicKey {
    e: u32,
    n: BigInt,
}

pub struct PrivateKey {
    d: u32,
    n: BigInt,
}

pub struct BnPublicKey {
    e: BigNum,
    n: BigNum,
}

pub struct BnPrivateKey {
    d: BigNum,
    n: BigNum,
}

pub struct PublicKeyGmp {
    e: Integer,
    n: Integer,
}

pub struct PrivateKeyGmp {
    d: Integer,
    n: Integer,
}

pub fn generate_keys(_key_len: usize) -> (PublicKey, PrivateKey) {
    // Key generation
    // https://datatracker.ietf.org/doc/html/rfc2313#section-6

    // RSA key length is the length of the modulus n in bits

    // 1. Choose two distinct primes p and q
    let p = BigInt::from(61);
    let q = BigInt::from(53);

    // 2. Compute the modulus, n = pq
    // n = 61 * 53 = 3233
    let n = p.clone() * q.clone();
    assert_eq!(n, BigInt::from(3233));

    // 3. Compute the totient, t
    // λ(3233) = lcm(60, 52) = 780
    let t = num::integer::lcm(p - 1, q - 1);
    assert_eq!(t, BigInt::from(780));

    // 4. Choose any number 1 < e < t that is coprime to t
    // Choosing a prime number for e leaves us only to check that e is not a divisor of t
    let e = 17;
    assert_eq!(num::integer::gcd(BigInt::from(e), t), BigInt::from(1));

    // 5. Compute d, the modular multiplicative inverse of e (mod t), yielding
    // modular multiplicative inverse: https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
    // 1 = (17 * 413) mod 780
    let d = 413;
    assert_eq!(d, 413);

    // 6. public key is (e = 17, n = 3233)
    let public_key = PublicKey { e, n: n.clone() };

    // 7. private key is (d = 413, n = 3233)
    let private_key = PrivateKey { d, n: n.clone() };

    (public_key, private_key)

    /*
        // my ~20 years old sample
        #include "flintpp.h"

        int nKeyLen=1024; // kalit uzunligi
        DWORD t1=GetTickCount();
        cout << "Kalitlar generatsiyasi ...";

        srand((unsigned int)time(NULL));

        // 2^(m-r-1) <= p < 2 ^ (m-r)
        // m = (m_KeyLen+1)/2, 2 <= r < 13 (r -random number)
        int m = (nKeyLen+1)/2 - (2+rand()%11);
        LINT p = findprime(m,1);

        // qmin = (2^(m_KeyLen-1)) / p+1
        LINT qmin = LINT(0).setbit(nKeyLen-1)/p+1;

        // qmax = 2^m_KeyLen/p
        LINT qmax = LINT(0).setbit(nKeyLen)/p;

        // qmin <= q <= qmax
        LINT q = findprime(qmin,qmax,1);

        LINT nModKey = p*q;
        LINT phi=(q-1)*(p-1); // эйлер функцияси

        seedBBS((unsigned long) time(NULL));
        LINT nPubKey=randBBS(nKeyLen);
        for(;;)
        {
            if (gcd(nPubKey,phi)==1)
                break;
            nPubKey++;
        }

        // d*e = 1(mod f(n))
        LINT nPrvKey=nPubKey.inv(phi);
    */
}

pub fn encrypt(m: &BigInt, public_key: &PublicKey) -> BigInt {
    m.pow(public_key.e) % public_key.n.clone()
}

pub fn decrypt(c: &BigInt, private_key: &PrivateKey) -> BigInt {
    c.pow(private_key.d) % private_key.n.clone()
}

#[cfg(test)]
mod tests {

    use num::BigInt;
    use openssl::bn::{BigNum, BigNumContext};

    use crate::*;

    #[test]
    fn wiki_sample_rsa_gmp() {
        // https://gitlab.com/tspiteri/rug       
        // https://gmplib.org/ 

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
        let public_key = PublicKeyGmp { e, n: n.clone() };

        // 7. private key is (d = 413, n = 3233)
        let private_key = PrivateKeyGmp { d, n: n.clone() };

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
    fn wiki_sample_rsa_openssl_bn() {
        let mut ctx = BigNumContext::new().unwrap();

        // 1. Choose two distinct primes p and q
        let p = BigNum::from_u32(61).unwrap();
        let q = BigNum::from_u32(53).unwrap();

        // 2. Compute the modulus, n = pq
        // n = 61 * 53 = 3233
        let n = &p * &q;
        assert_eq!(n, BigNum::from_u32(3233).unwrap());

        // 3. Compute the totient, t
        // λ(3233) = lcm(60, 52) = 780
        // openssl uses Euler's totient function
        // t = (p − 1) * (q − 1)
        // https://crypto.stackexchange.com/questions/94926/rsa-private-exponent-generation-according-to-fips-186-4-in-openssl-v1
        let one = BigNum::from_u32(1).unwrap();
        let mut p1 = BigNum::new().unwrap();
        p1.checked_sub(&p, &one).unwrap();
        let mut q1 = BigNum::new().unwrap();
        q1.checked_sub(&q, &one).unwrap();
        let t = &p1 * &q1;

        // there is no lcm() in openssl!!!
        let t = BigNum::from_u32(780).unwrap();
        assert_eq!(t, BigNum::from_u32(780).unwrap());

        // 4. Choose any number 1 < e < t that is coprime to t
        // Choosing a prime number for e leaves us only to check that e is not a divisor of t
        let e =  BigNum::from_u32(17).unwrap();
        let mut gcd = BigNum::new().unwrap();
        gcd.gcd(&e, &t, &mut ctx).unwrap();
        assert_eq!(gcd, BigNum::from_u32(1).unwrap());

        // 5. Compute d
        // 1 = (17 * 413) mod 780
        let mut d = BigNum::new().unwrap();
        d.mod_inverse(&e, &t, &mut ctx).unwrap();
        assert_eq!(d, BigNum::from_u32(413).unwrap());

        let n_slice = n.to_vec();

        // 6. public key is (e = 17, n = 3233)
        let public_key = BnPublicKey { e, n: BigNum::from_slice(&n_slice).unwrap()};

        // 7. private key is (d = 413, n = 3233)
        let private_key = BnPrivateKey { d, n: BigNum::from_slice(&n_slice).unwrap() };

        // message, m = 65
        let m = BigNum::from_u32(65).unwrap();

        // 8. encryption
        // c = (m ^ e) mod n
        let mut c = BigNum::new().unwrap();
        c.mod_exp(&m, &public_key.e, &public_key.n, &mut ctx).unwrap();
        assert_eq!(c.to_string(), "2790");

        // 9. decryption
        // D = (c ^ d) mod n
        let mut dm = BigNum::new().unwrap();
        dm.mod_exp(&c, &private_key.d, &private_key.n, &mut ctx).unwrap();
        assert_eq!(dm.to_string(), "65");

        assert_eq!(m, dm);
    }

    #[test]
    fn wiki_sample_rsa_num() {
        // 1. Choose two distinct primes p and q
        let p = BigInt::from(61);
        let q = BigInt::from(53);

        // 2. Compute the modulus, n = pq
        // n = 61 * 53 = 3233
        let n = p.clone() * q.clone();
        assert_eq!(n, BigInt::from(3233));

        // 3. Compute the totient, t
        // λ(3233) = lcm(60, 52) = 780
        let t = num::integer::lcm(p - 1, q - 1);
        assert_eq!(t, BigInt::from(780));

        // 4. Choose any number 1 < e < t that is coprime to t
        // Choosing a prime number for e leaves us only to check that e is not a divisor of t
        let e = 17;
        assert_eq!(num::integer::gcd(BigInt::from(e), t), BigInt::from(1));

        // 5. Compute d
        // 1 = (17 * 413) mod 780
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

    #[test]
    fn rsa_test() {
        let (public_key, private_key) = generate_keys(4096);

        // message, m = 65
        let m = BigInt::from(65);

        // encryption
        let c = encrypt(&m, &public_key);
        assert_eq!(c.to_string(), "2790");

        // decryption
        let dm = decrypt(&c, &private_key);
        assert_eq!(dm.to_string(), "65");

        assert_eq!(m, dm);
    }
}
