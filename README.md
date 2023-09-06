# RSA (Rivest–Shamir–Adleman) asymmetric cipher in Rust

A sample implementation of RSA (Rivest–Shamir–Adleman) public-key cryptosystem for learning purposes

## Key generation

```text
1. Choose two distinct primes p and q

2. Compute the modulus, n = p * q

3. Compute the totient, t
    - Euler's totient function is used in the original RSA
        φ(n) = (p − 1) * (q − 1)
        which outputs the amount of numbers that are coprime to n
    - Carmichael function is recommended in the modern RSA-based cryptosystems
        https://en.wikipedia.org/wiki/Carmichael_function
        also known as reduced totient function or least universal exponent function
        λ(n) = lcm(p − 1, q − 1)
        where lcm() is least common multiple: https://en.wikipedia.org/wiki/Least_common_multiple

4. Choose a public key exponent, integer e (usually 65537 = 0x010001)
    1 < e < t and gcd(t, e) = 1

5. Compute d, the modular multiplicative inverse of e (mod t)
    modular multiplicative inverse: https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
    d = (e ^ (−1)) mod t
    or 
    1 = (d * e) mod t

6. Public key = (e, n)

7. Private key = (d, n)
```

The numbers p, q, and d must be kept secret

## Encryption

Encryption of plaintext message, m

```text
    c = (m ^ e) mod n
```

## Decryption

Decryption of ciphertext, c

```text
    D = (c ^ d) mod n
```
