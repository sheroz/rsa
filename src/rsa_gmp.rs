// https://gitlab.com/tspiteri/rug       
// https://gmplib.org/ 

use rug::Integer;

pub struct PublicKey {
    e: Integer,
    n: Integer,
}

pub struct PrivateKey {
    d: Integer,
    n: Integer,
}

pub fn generate_keys(_key_len: usize) -> (PublicKey, PrivateKey) {
    // Key generation
    // https://datatracker.ietf.org/doc/html/rfc2313#section-6

    // RSA key length is the length of the modulus n in bits
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
    fn rsa_test() {
        let (public_key, private_key) = generate_keys(4096);

        // message, m = 65
        let m = Integer::from(65);

        // encryption
        let c = encrypt(m.clone(), &public_key);
        assert_eq!(c, 2790);

        // decryption
        let dm = decrypt(c, &private_key);
        assert_eq!(dm, 65);

        assert_eq!(m, dm);
    }
}
