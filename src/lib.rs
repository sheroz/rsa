// https://en.wikipedia.org/wiki/RSA_(cryptosystem)
// RSA: https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture12.pdf
// https://asecuritysite.com/rust/rsa01
// https://blog.cloudflare.com/searching-for-the-prime-suspect-how-heartbleed-leaked-private-keys/
// https://www.lightbluetouchpaper.org/2014/04/25/heartbleed-and-rsa-private-keys/

use num::BigInt;

/*
    Key generation
    1. Choose two distinct primes p and q
    2. Compute the modulus, n = p * q
    3. Compute the totient φ(n) = (p − 1) * (q − 1)
    4. Choose an integer e
        1 < e < φ(n) and gcd(φ(n), e) = 1
    5. Compute d, the modular multiplicative inverse of e (mod φ(n))
        d = e−1 mod φ(n) or 1 = (d * e) mod φ(n)
    6. Public Key = (e, n)
    7. Private Key = (d, n)
    8. Encryption of plaintext message, m
        c = (m ^ e) mod n 
    9. Decryption of ciphertext, c
        m = (c ^ d) mod n
*/

pub struct PublicKey {
    e: u32,
    n: BigInt
}

pub struct PrivateKey {
    d: u32,
    n: BigInt
}

pub fn generate_keys() -> (PublicKey, PrivateKey) {
        // 1. Choose two distinct primes p and q
        let p = BigInt::from(61);
        let q = BigInt::from(53);
    
        // 2. Compute the modulus, n = pq
        // n = 61 * 53 = 3233
        let n = p * q;
        assert_eq!(n, BigInt::from(3233));
    
        // 3. Compute the totient function, https://en.wikipedia.org/wiki/Carmichael_function 
        // of the product as λ(n) = lcm(p − 1, q − 1),
        // least common multiple, lcm: https://en.wikipedia.org/wiki/Least_common_multiple
        // λ(3233) = lcm(60,52) = 780
        let _lcm = 780;
    
        // 4. Choose any number 1 < e < 780 that is coprime to 780.
        // Choosing a prime number for e leaves us only to check that e is not a divisor of 780. 
        let e = 17;
    
        // 5. Compute d, the modular multiplicative inverse of e (mod λ(n)), yielding
        // modular multiplicative inverse: https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
        // 1 = (17 * 413) mod 780
        let d = 413;
    
        // 6. public key is (e = 17, n = 3233)
        let public_key = PublicKey { e, n: n.clone()};
    
        // 7. private key is (d = 413, n = 3233)
        let private_key = PrivateKey { d, n: n.clone() };

        (public_key, private_key)

/*
    #include "flintpp.h"
    // C library: https://flintlib.org/

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
    // 8. encryption
    // c = (m ^ e) mod n

    let e = public_key.e;
    let n = public_key.n.clone();
    m.pow(e) % n 
}

pub fn decrypt(c: &BigInt, private_key: &PrivateKey) -> BigInt {
    // 9. decryption
    // m = (c ^ d) mod n

    let d = private_key.d;
    let n = private_key.n.clone();
    c.pow(d) % n
}
    
#[cfg(test)]
mod tests {

    use num::BigInt;

    use crate::*;

    #[test]
    pub fn wiki_sample_rsa() {
    
        let (public_key, private_key) = generate_keys();

        // message, m = 65
        let m = BigInt::from(65);

        // encryption
        let cm = encrypt(&m, &public_key);

        // decryption
        let m_c = decrypt(&cm, &private_key);

        assert_eq!(m, m_c);
    }
}