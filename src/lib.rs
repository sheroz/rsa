// RSA: https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture12.pdf
// https://blog.cloudflare.com/searching-for-the-prime-suspect-how-heartbleed-leaked-private-keys/
// https://www.lightbluetouchpaper.org/2014/04/25/heartbleed-and-rsa-private-keys/

// https://medium.com/snips-ai/prime-number-generation-2a02f28508ff
// https://github.com/AtropineTears/num-primes

pub mod rsa_gmp;
pub mod rsa_num;
pub mod rsa_openssl_bn;

pub use rsa_gmp::*;
