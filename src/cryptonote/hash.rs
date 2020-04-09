// Rust Monero Library
// Written in 2019 by
//   h4sh3d <h4sh3d@protonmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//

//! CryptoNote hash structures and functions
//!
//! Support for (de)serializable hashes (Keccak 256) and `Hn` (hash to number, or hash to scalar).
//!

use crate::{
    consensus::encode::{self, Decodable, Decoder, Encodable, Encoder},
    util::key::PrivateKey,
};
use curve25519_dalek::scalar::Scalar;
use keccak_hash::keccak_256;
#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

fixed_hash::construct_fixed_hash!(
    /// Result of a Keccak-256
    #[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
    pub struct Hash(32);
);

impl Hash {
    /// Create a null hash with all zeros
    #[must_use]
    pub const fn null_hash() -> Self {
        Self([0_u8; 32])
    }

    /// Hash a stream of bytes with Keccak 256
    #[must_use]
    pub fn hash(input: &[u8]) -> Self {
        let mut out = [0_u8; 32];
        keccak_256(input, &mut out);
        Self(out)
    }

    /// Return the hash value
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Return the scalar of the hash as a little endian number modulo l (curve order)
    #[must_use]
    pub fn as_scalar(&self) -> PrivateKey {
        PrivateKey::from_scalar(Scalar::from_bytes_mod_order(self.0))
    }

    /// Hash a stream of bytes and return its scalar representation
    ///
    /// The hash function H is the same Keccak function that is used in CryptoNote. When the
    /// value of the hash function is interpreted as a scalar, it is converted into a
    /// little-endian integer and taken modulo l.
    #[must_use]
    pub fn hash_to_scalar(input: &[u8]) -> PrivateKey {
        Self::hash(input).as_scalar()
    }
}

impl<D: Decoder> Decodable<D> for Hash {
    fn consensus_decode(d: &mut D) -> Result<Self, encode::Error> {
        Ok(Self(Decodable::consensus_decode(d)?))
    }
}

impl<S: Encoder> Encodable<S> for Hash {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.0.consensus_encode(s)
    }
}

/// Capacity of an object to hash itself
pub trait Hashable {
    /// Return its own hash
    fn hash(&self) -> Hash;

    /// Apply `hash_to_scalar` on itself and return the scalar
    fn hash_to_scalar(&self) -> PrivateKey {
        self.hash().as_scalar()
    }
}

fixed_hash::construct_fixed_hash!(
    /// 8 bytes hash
    #[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
    pub struct Hash8(8);
);

impl<D: Decoder> Decodable<D> for Hash8 {
    fn consensus_decode(d: &mut D) -> Result<Self, encode::Error> {
        Ok(Self(Decodable::consensus_decode(d)?))
    }
}

impl<S: Encoder> Encodable<S> for Hash8 {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.0.consensus_encode(s)
    }
}
