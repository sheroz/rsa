# RSA (Rivest–Shamir–Adleman) Asymmetric Cipher in Rust

Samples of RSA (Rivest–Shamir–Adleman) public-key cryptosystem implementations for learning purposes

- [src/rsa_gmp.rs](src/rsa_gmp.rs) - uses a [rug](https://crates.io/crates/rug), a high-level interface to the wrapper over [GNU MP / GMP](https://gmplib.org/), a well known arbitrary precision arithmetic library
- [src/rsa_openssl_bn.rs](src/rsa_openssl_bn.rs) - uses an [openssl](https://crates.io/crates/openssl), a safe interface to the popular [OpenSSL library](https://www.openssl.org/)
- [src/rsa_num.rs](src/rsa_num.rs) - uses a [num](https://crates.io/crates/num), a collection of numeric types and traits in pure Rust

## Key generation

1. Choose two distinct primes `p` and `q`

   FIPS.186-4, Section: B.3.1 Criteria for IFC Key Pairs

   ```text
   sqrt(2)*2^((nlen/2)-1) <= p <= 2^(nlen/2)-1

   sqrt(2)*2^((nlen/2)-1) <= q <= 2^(nlen/2)-1

   |p - q| > 2^((nlen/2)-100)  
   ```

   where:

   `^` is an exponentiation (power) arithmetic operation

   `nlen` is the appropriate length for the desired security strength

2. Compute the modulus, `n`

   ```text
   n = p * q
   ```

3. Compute the totient, `t`

- `Euler's totient function` is used in the original RSA

   ```text
   φ(n) = (p − 1) * (q − 1)
   ```

   which outputs the amount of numbers that are coprime to `n`

- [Carmichael function](https://en.wikipedia.org/wiki/Carmichael_function) is recommended for modern RSA-based cryptosystems, also known as `reduced totient function` or `least universal exponent function`

   ```text
   λ(n) = lcm(p − 1, q − 1)
   ```

   where `lcm()` is the [least common multiple](https://en.wikipedia.org/wiki/Least_common_multiple)

4. Choose a public key exponent, integer `e` (usually `65537` in decimal, or `0x010001` in hex)

   ```text
   1 < e < t
   gcd(t, e) = 1
   ```

5. Compute the [modular multiplicative inverse](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse), `d`

   ```text
   d = (e ^ (−1)) mod t
   1 = (d * e) mod t
   ```

6. Public key

   ```text
   (e, n)
   ```

7. Private key

   ```text
   (d, n)
   ```

The numbers `p`, `q`, and `d` must be kept secret

## Encryption

The encryption of the plaintext message, `m`

```text
c = (m ^ e) mod n
```

## Decryption

The decryption of the ciphertext, `c`

```text
D = (c ^ d) mod n
```

## References

- [RSA in Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [FIPS 186-4, Key Pair Generation](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf#page=62)

## Disclaimer

This project was created for research purposes and is not intended for use in production systems.
