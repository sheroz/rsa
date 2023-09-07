# RSA (Rivest–Shamir–Adleman) asymmetric cipher in Rust

Samples of RSA (Rivest–Shamir–Adleman) public-key cryptosystem implementations for learning purposes

## Test samples by using

- [rug](https://crates.io/crates/rug) - a high-level interface to the wrapper over [GMP](https://gmplib.org/), a well known arbitrary precision arithmetic library
- [openssl](https://crates.io/crates/openssl) - a safe interface to the popular [OpenSSL library](https://www.openssl.org/)
- [num](https://crates.io/crates/num) - A collection of numeric types and traits in pure Rust

## Key generation

```text
1. Choose two distinct primes p and q

2. Compute the modulus, n = p * q

3. Compute the totient, t
    - Euler's totient function is used in the original RSA

        φ(n) = (p − 1) * (q − 1)

        which outputs the amount of numbers that are coprime to n

    - Carmichael function is recommended for modern RSA-based cryptosystems,
        also known as reduced totient function or
        least universal exponent function:
        https://en.wikipedia.org/wiki/Carmichael_function

        λ(n) = lcm(p − 1, q − 1)

        where lcm() is the least common multiple:
        https://en.wikipedia.org/wiki/Least_common_multiple

4. Choose a public key exponent, integer e (usually 65537 = 0x010001)
    1 < e < t and gcd(t, e) = 1

5. Compute the d, modular multiplicative inverse of e (mod t)
    Modular multiplicative inverse:
    https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
    
    d = (e ^ (−1)) mod t
    or 
    1 = (d * e) mod t

6. Public key = (e, n)

7. Private key = (d, n)
```

The numbers p, q, and d must be kept secret

## Encryption

The encryption of the plaintext message, m

```text
c = (m ^ e) mod n
```

## Decryption

The decryption of the ciphertext, c

```text
D = (c ^ d) mod n
```
