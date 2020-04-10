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

//! RingCT primitive types
//!
//! Support for parsing RingCT signature in Monero transactions.
//!

use crate::{
    consensus::encode::{self, serialize, Decodable, Decoder, Encodable, Encoder, VarInt},
    cryptonote::hash,
};
#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde_support")]
use serde_big_array_unchecked_docs::*;
use std::{convert::TryFrom, fmt};

///Serde support for array's bigger than 32
#[allow(missing_docs)]
#[cfg(feature = "serde_support")]
pub mod serde_big_array_unchecked_docs {
    use serde_big_array::big_array;
    big_array! { BigArray; }
}

/// RingCT possible errors
#[derive(Debug)]
pub enum Error {
    /// Invalid RingCT type
    UnknownRctType,
}

// ====================================================================
/// Raw 32 bytes key
#[derive(Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct Key {
    /// The actual key
    pub key: [u8; 32],
}

impl_hex_display!(Key, key);

impl_consensus_encoding!(Key, key);

// ====================================================================
/// Raw 64 bytes key
#[derive(Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct Key64 {
    /// The actual key
    #[cfg_attr(feature = "serde_support", serde(with = "BigArray"))]
    pub key: [u8; 64],
}

impl_hex_display!(Key64, key);

impl_consensus_encoding!(Key64, key);

// ====================================================================
/// Confidential transaction key
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct CtKey {
    //pub dest: Key,
    /// Mask
    pub mask: Key,
}

impl_consensus_encoding!(CtKey, mask);

// ====================================================================
/// Multisig
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct MultisigKLRki {
    /// K value
    pub K: Key,
    /// L value
    pub L: Key,
    /// R value
    pub R: Key,
    /// ki value
    pub ki: Key,
}

impl_consensus_encoding!(MultisigKLRki, K, L, R, ki);

// ====================================================================
/// Vector of multisig output keys
#[derive(Debug)]
pub struct MultisigOut {
    /// Vector of keys
    pub c: Vec<Key>,
}

impl_consensus_encoding!(MultisigOut, c);

// ====================================================================
/// Diffie-Hellman info
/// Mask and amount for transaction before Bulletproof2 and only 8 bytes hash for the amount in
/// Bulletproof2 type
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub enum EcdhInfo {
    /// Standard format, before bp2
    Standard {
        /// Mask value
        mask: Key,
        /// Amount value
        amount: Key,
    },
    /// bp2 format
    Bulletproof2 {
        /// Amount value
        amount: hash::Hash8,
    },
}

impl EcdhInfo {
    /// Decode Diffie-Hellman info given the RingCT type
    fn consensus_decode<D: Decoder>(d: &mut D, rct_type: RctType) -> Result<Self, encode::Error> {
        match rct_type {
            RctType::Full | RctType::Simple | RctType::Bulletproof | RctType::Null => {
                Ok(Self::Standard {
                    mask: Decodable::consensus_decode(d)?,
                    amount: Decodable::consensus_decode(d)?,
                })
            }
            RctType::Bulletproof2 => Ok(Self::Bulletproof2 {
                amount: Decodable::consensus_decode(d)?,
            }),
        }
    }
}

impl<S: Encoder> Encodable<S> for EcdhInfo {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        match self {
            Self::Standard { mask, amount } => {
                mask.consensus_encode(s)?;
                amount.consensus_encode(s)?;
            }
            Self::Bulletproof2 { amount } => {
                amount.consensus_encode(s)?;
            }
        }
        Ok(())
    }
}

// ====================================================================
/// Borromean signature for range commitment
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct BoroSig {
    /// s0 value
    pub s0: Key64,
    /// s1 value
    pub s1: Key64,
    /// ee value
    pub ee: Key,
}

impl_consensus_encoding!(BoroSig, s0, s1, ee);

// ====================================================================
/// Mg sig
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct MgSig {
    /// Matrice of keys
    pub ss: Vec<Vec<Key>>,
    /// cc value
    pub cc: Key,
}

impl<S: Encoder> Encodable<S> for MgSig {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        for ss in &self.ss {
            encode_sized_vec!(ss, s);
        }
        self.cc.consensus_encode(s)
    }
}

// ====================================================================
/// Range signature for range commitment
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct RangeSig {
    /// asig value
    pub asig: BoroSig,
    /// Ci value
    pub Ci: Key64,
}

impl_consensus_encoding!(RangeSig, asig, Ci);

// ====================================================================
/// Bulletproof format
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct Bulletproof {
    /// A value
    pub A: Key,
    /// S value
    pub S: Key,
    /// T1 value
    pub T1: Key,
    /// T2 value
    pub T2: Key,
    /// taux value
    pub taux: Key,
    /// mu value
    pub mu: Key,
    /// L value
    pub L: Vec<Key>,
    /// R value
    pub R: Vec<Key>,
    /// a value
    pub a: Key,
    /// b value
    pub b: Key,
    /// t value
    pub t: Key,
}

impl_consensus_encoding!(Bulletproof, A, S, T1, T2, taux, mu, L, R, a, b, t);

// ====================================================================
/// RingCT base signature format
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct RctSigBase {
    /// The RingCT type of signatures
    pub rct_type: RctType,
    /// Transaction fee
    pub txn_fee: VarInt,
    //pub message: Key,
    //pub mix_ring: Vec<Vec<CtKey>>,
    /// Pseudo outs key vector
    pub pseudo_outs: Vec<Key>,
    /// Ecdh info vector
    pub ecdh_info: Vec<EcdhInfo>,
    /// Out pk vector
    pub out_pk: Vec<CtKey>,
}

impl RctSigBase {
    /// Decode a RingCT base signature given the number of inputs and outputs of the transaction
    pub fn consensus_decode<D: Decoder>(
        d: &mut D,
        inputs: usize,
        outputs: usize,
    ) -> Result<Option<Self>, encode::Error> {
        let rct_type: RctType = Decodable::consensus_decode(d)?;
        match rct_type {
            RctType::Null => Ok(None),
            RctType::Full | RctType::Simple | RctType::Bulletproof | RctType::Bulletproof2 => {
                let mut pseudo_outs: Vec<Key> = vec![];
                // TxnFee
                let txn_fee: VarInt = Decodable::consensus_decode(d)?;
                // RctType
                if rct_type == RctType::Simple {
                    pseudo_outs = decode_sized_vec!(inputs, d);
                }
                // EcdhInfo
                let mut ecdh_info: Vec<EcdhInfo> = vec![];
                for _ in 0..outputs {
                    ecdh_info.push(EcdhInfo::consensus_decode(d, rct_type)?);
                }
                // OutPk
                let out_pk: Vec<CtKey> = decode_sized_vec!(outputs, d);
                Ok(Some(Self {
                    rct_type,
                    txn_fee,
                    pseudo_outs,
                    ecdh_info,
                    out_pk,
                }))
            }
        }
    }
}

impl<S: Encoder> Encodable<S> for RctSigBase {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.rct_type.consensus_encode(s)?;
        match self.rct_type {
            RctType::Null => Ok(()),
            RctType::Full | RctType::Simple | RctType::Bulletproof | RctType::Bulletproof2 => {
                self.txn_fee.consensus_encode(s)?;
                if self.rct_type == RctType::Simple {
                    encode_sized_vec!(self.pseudo_outs, s);
                }
                encode_sized_vec!(self.ecdh_info, s);
                encode_sized_vec!(self.out_pk, s);
                Ok(())
            }
        }
    }
}

impl hash::Hashable for RctSigBase {
    fn hash(&self) -> hash::Hash {
        hash::Hash::hash(&serialize(self))
    }
}

// ====================================================================
/// RingCT types
#[derive(Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub enum RctType {
    /// Null type
    Null,
    /// Full type
    Full,
    /// Simple type
    Simple,
    /// First Bulletproof type
    Bulletproof,
    /// Bulletproof2 type, used in the current network
    Bulletproof2,
}

impl RctType {
    /// Return if the format use one of the bulletproof format
    #[must_use]
    pub fn is_rct_bp(self) -> bool {
        match self {
            Self::Bulletproof | Self::Bulletproof2 => true,
            _ => false,
        }
    }
}

impl<D: Decoder> Decodable<D> for RctType {
    fn consensus_decode(d: &mut D) -> Result<Self, encode::Error> {
        let rct_type: u8 = Decodable::consensus_decode(d)?;
        match rct_type {
            0 => Ok(Self::Null),
            1 => Ok(Self::Full),
            2 => Ok(Self::Simple),
            3 => Ok(Self::Bulletproof),
            4 => Ok(Self::Bulletproof2),
            _ => Err(Error::UnknownRctType.into()),
        }
    }
}

impl<S: Encoder> Encodable<S> for RctType {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        match self {
            Self::Null => 0_u8.consensus_encode(s)?,
            Self::Full => 1_u8.consensus_encode(s)?,
            Self::Simple => 2_u8.consensus_encode(s)?,
            Self::Bulletproof => 3_u8.consensus_encode(s)?,
            Self::Bulletproof2 => 4_u8.consensus_encode(s)?,
        }
        Ok(())
    }
}

// ====================================================================
/// Prunable part of RingCT signature format
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct RctSigPrunable {
    /// Range signatures
    pub range_sigs: Vec<RangeSig>,
    /// Bulletproofs
    pub bulletproofs: Vec<Bulletproof>,
    /// MG signatures
    pub MGs: Vec<MgSig>,
    /// Pseudo out vector
    pub pseudo_outs: Vec<Key>,
}

impl RctSigPrunable {
    /// Decode a prunable RingCT signature given the number of inputs and outputs in the
    /// transaction, the RingCT type and the number of mixins
    #[allow(non_snake_case)]
    pub fn consensus_decode<D: Decoder>(
        d: &mut D,
        rct_type: RctType,
        inputs: usize,
        outputs: usize,
        mixin: usize,
    ) -> Result<Option<Self>, encode::Error> {
        match rct_type {
            RctType::Null => Ok(None),
            RctType::Full | RctType::Simple | RctType::Bulletproof | RctType::Bulletproof2 => {
                let mut bulletproofs: Vec<Bulletproof> = vec![];
                let mut range_sigs: Vec<RangeSig> = vec![];
                if rct_type.is_rct_bp() {
                    if let RctType::Bulletproof2 = rct_type {
                        bulletproofs = Decodable::consensus_decode(d)?;
                    } else {
                        let size: u32 = Decodable::consensus_decode(d)?;
                        bulletproofs = decode_sized_vec!(size, d);
                    };
                } else {
                    range_sigs = decode_sized_vec!(outputs, d);
                }

                let is_full = rct_type == RctType::Full;
                let mg_elements = if is_full { 1 } else { inputs };
                let mut MGs: Vec<MgSig> = vec![];
                for _ in 0..mg_elements {
                    let mut ss: Vec<Vec<Key>> = vec![];
                    for _ in 0..=mixin {
                        let mg_ss2_elements = if is_full { 1 + inputs } else { 2 };
                        let ss_elems: Vec<Key> = decode_sized_vec!(mg_ss2_elements, d);
                        ss.push(ss_elems);
                    }
                    let cc = Decodable::consensus_decode(d)?;
                    MGs.push(MgSig { ss, cc });
                }

                let mut pseudo_outs: Vec<Key> = vec![];
                match rct_type {
                    RctType::Bulletproof | RctType::Bulletproof2 => {
                        pseudo_outs = decode_sized_vec!(inputs, d);
                    }
                    _ => (),
                }
                Ok(Some(Self {
                    range_sigs,
                    bulletproofs,
                    MGs,
                    pseudo_outs,
                }))
            }
        }
    }

    /// Encode the prunable RingCT signature part given the RingCT type of the transaction
    pub fn consensus_encode<S: Encoder>(
        &self,
        s: &mut S,
        rct_type: RctType,
    ) -> Result<(), encode::Error> {
        match rct_type {
            RctType::Null => Ok(()),
            RctType::Full | RctType::Simple | RctType::Bulletproof | RctType::Bulletproof2 => {
                if rct_type.is_rct_bp() {
                    if let RctType::Bulletproof2 = rct_type {
                        self.bulletproofs.consensus_encode(s)?;
                    } else {
                        let size: u32 =
                            u32::try_from(self.bulletproofs.len()).unwrap_or(u32::max_value());
                        size.consensus_encode(s)?;
                        encode_sized_vec!(self.bulletproofs, s);
                    }
                } else {
                    encode_sized_vec!(self.range_sigs, s);
                }
                encode_sized_vec!(self.MGs, s);
                match rct_type {
                    RctType::Bulletproof | RctType::Bulletproof2 => {
                        encode_sized_vec!(self.pseudo_outs, s);
                    }
                    _ => (),
                }
                Ok(())
            }
        }
    }
}

// ====================================================================
/// A RingCT signature
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct RctSig {
    /// The base part
    pub sig: Option<RctSigBase>,
    /// The prunable part
    pub p: Option<RctSigPrunable>,
}

// ====================================================================
/// A raw signature
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct Signature {
    /// c value
    pub c: Key,
    /// r value
    pub r: Key,
}

impl_consensus_encoding!(Signature, c, r);
