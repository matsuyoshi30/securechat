use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, ToPrimitive, Zero};
use rand::{self, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[derive(Clone, Debug)]
pub struct PublicKey {
    e: BigUint,     // Exponent
    pub n: BigUint, // n = p*q
}

impl PublicKey {
    pub fn encrypt(&self, m: &BigUint) -> BigUint {
        m.modpow(&self.e, &self.n)
    }
}

#[derive(Clone)]
pub struct PrivateKey {
    p: BigUint, // First prime factor: p
    q: BigUint, // Second prime factor: q
    d: BigUint, // d - multiplicative inverse of e mod n
}

impl PrivateKey {
    pub fn decrypt(&self, c: &BigUint) -> BigUint {
        c.modpow(&self.d, &(&self.p * &self.q))
    }
}

#[derive(Clone)]
pub struct Keypair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl Keypair {
    pub fn new(p: Option<BigUint>, q: Option<BigUint>) -> Keypair {
        // TODO: check p and q are prime

        const RSA_EXP: u64 = 65537;

        let p = if let Some(p) = p { p } else { gen_prime(1024) };
        let q = if let Some(q) = q { q } else { gen_prime(1024) };
        let e = BigUint::from(RSA_EXP);
        let n = &p * &q;
        let phi_n = (&p - 1u64) * (&q - 1u64); // φ
        let d = e.modinv(&phi_n).unwrap();
        let public = PublicKey { e, n };
        let private = PrivateKey { p, q, d };

        Keypair { public, private }
    }

    pub fn validate(&self, m: &BigUint, s: &BigUint) -> bool {
        s.modpow(&self.public.e, &self.public.n) == *m
    }

    pub fn sign(&self, m: &BigUint) -> BigUint {
        m.modpow(&self.private.d, &self.public.n)
    }
}

pub fn gen_prime(bits: u64) -> BigUint {
    let mut rng = ChaCha20Rng::from_entropy();
    let byte_len = (bits / 8) as usize;

    loop {
        let mut bytes = vec![0u8; byte_len];
        rng.fill_bytes(&mut bytes);
        let candidate = BigUint::from_bytes_be(&bytes);

        if candidate.bits() == bits && miller_rabin_test(&candidate, 12, &mut rng) {
            return candidate;
        }
    }
}

fn miller_rabin_test(n: &BigUint, k: usize, rng: &mut ChaCha20Rng) -> bool {
    if n <= &BigUint::from(2u64) {
        return false;
    }
    if n % 2u64 == BigUint::zero() {
        return false;
    }

    let (s, d) = factor(&(n - 1u64));

    'outer: for _ in 0..k {
        let a = rng.gen_biguint_range(&BigUint::from(2u64), &(n - 2u64));
        let mut x = a.modpow(&d, n);

        if x == BigUint::one() || x == n - 1u64 {
            continue;
        }

        for _ in 1..s.to_usize().unwrap() {
            x = x.modpow(&BigUint::from(2u64), n);

            if x == BigUint::one() {
                return false;
            }
            if x == n - 1u64 {
                continue 'outer;
            }
        }

        return false;
    }

    true
}

fn factor(n: &BigUint) -> (BigUint, BigUint) {
    let mut s: BigUint = BigUint::from(0u64);
    let mut d = n.clone();

    while &d % 2u64 == BigUint::zero() {
        s += BigUint::one();
        d /= 2u64;
    }

    (s, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::FromPrimitive;

    #[test]
    fn test_gen_prime() {
        let bits = 128;
        let prime = gen_prime(bits);
        assert_eq!(prime.bits(), bits);
        assert!(miller_rabin_test(
            &prime,
            12,
            &mut ChaCha20Rng::from_entropy()
        ));
    }

    #[test]
    fn test_miller_rabin_test() {
        let mut rng = ChaCha20Rng::from_entropy();
        let prime = BigUint::from_u64(61).unwrap();
        assert!(miller_rabin_test(&prime, 12, &mut rng));

        let composite = BigUint::from_u64(60).unwrap();
        assert!(!miller_rabin_test(&composite, 12, &mut rng));
    }

    #[test]
    fn test_factor() {
        let n = BigUint::from_u64(56).unwrap();
        let (s, d) = factor(&n);
        assert_eq!(s, BigUint::from_u64(3).unwrap());
        assert_eq!(d, BigUint::from_u64(7).unwrap());
    }
}
