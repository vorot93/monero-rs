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

//! # Addresses
//!
//! Support for (de)serializable Monero addresses in Monero base58 format.
//!
//! ## Parsing an address
//!
//! ```rust
//! use std::str::FromStr;
//! use monero::Address;
//! use monero::util::address::Error;
//!
//! let address = Address::from_str("4ADT1BtbxqEWeMKp9GgPr2NeyJXXtNxvoDawpyA4WpzFcGcoHUvXeijE66DNfohE9r1bQYaBiQjEtKE7CtkTdLwiDznFzra")?;
//!
//! let public_spend_key = address.public_spend;
//! let public_view_key = address.public_view;
//! # Ok::<(), Error>(())
//! ```
//!
//! ## Payment Id
//!
//! ```rust
//! use std::str::FromStr;
//! use monero::Address;
//! use monero::util::address::{AddressType, Error, PaymentId};
//!
//! let address = Address::from_str("4Byr22j9M2878Mtyb3fEPcBNwBZf5EXqn1Yi6VzR46618SFBrYysab2Cs1474CVDbsh94AJq7vuV3Z2DRq4zLcY3LHzo1Nbv3d8J6VhvCV")?;
//!
//! let payment_id = PaymentId([88, 118, 184, 183, 41, 150, 255, 151]);
//! assert_eq!(address.addr_type, AddressType::Integrated(payment_id));
//! # Ok::<(), Error>(())
//! ```
//!

use crate::{
    network::{self, Network},
    util::key::{KeyPair, PublicKey, ViewPair},
};
use base58_monero::base58;
use keccak_hash::keccak_256;
use std::{error, fmt, str::FromStr};

/// Possible errors when manipulating addresses
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Invalid address magic byte
    InvalidMagicByte,
    /// Invalid payment id
    InvalidPaymentId,
    /// Missmatch checksums
    InvalidChecksum,
    /// Invalid format
    InvalidFormat,
    /// Monero base58 error
    Base58(base58::Error),
    /// Network error
    Network(network::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Base58(e) => return fmt::Display::fmt(e, f),
                Self::Network(e) => return fmt::Display::fmt(e, f),
                Self::InvalidMagicByte => "invalid magic byte",
                Self::InvalidPaymentId => "invalid payment id",
                Self::InvalidChecksum => "checksums missmatch",
                Self::InvalidFormat => "invalid format",
            }
        )
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Base58(e) => Some(e),
            Self::Network(e) => Some(e),
            Self::InvalidMagicByte
            | Self::InvalidPaymentId
            | Self::InvalidChecksum
            | Self::InvalidFormat => None,
        }
    }
}

#[doc(hidden)]
impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Self {
        Self::Base58(e)
    }
}

#[doc(hidden)]
impl From<network::Error> for Error {
    fn from(e: network::Error) -> Self {
        Self::Network(e)
    }
}

/// Address type: standard, integrated, or sub address
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AddressType {
    /// Standard address
    Standard,
    /// Address with 8 bytes payment id
    Integrated(PaymentId),
    /// Subaddress
    SubAddress,
}

impl AddressType {
    /// Recover the address type given an address bytes and the network
    pub fn from_slice(bytes: &[u8], net: Network) -> Result<Self, Error> {
        let byte = bytes[0];
        match net {
            Network::Mainnet => match byte {
                18 => Ok(Self::Standard),
                19 => {
                    let payment_id = PaymentId::from_slice(&bytes[65..73]);
                    Ok(Self::Integrated(payment_id))
                }
                42 => Ok(Self::SubAddress),
                _ => Err(Error::InvalidMagicByte),
            },
            Network::Testnet => match byte {
                53 => Ok(Self::Standard),
                54 => {
                    let payment_id = PaymentId::from_slice(&bytes[65..73]);
                    Ok(Self::Integrated(payment_id))
                }
                63 => Ok(Self::SubAddress),
                _ => Err(Error::InvalidMagicByte),
            },
            Network::Stagenet => match byte {
                24 => Ok(Self::Standard),
                25 => {
                    let payment_id = PaymentId::from_slice(&bytes[65..73]);
                    Ok(Self::Integrated(payment_id))
                }
                36 => Ok(Self::SubAddress),
                _ => Err(Error::InvalidMagicByte),
            },
        }
    }
}

impl Default for AddressType {
    fn default() -> Self {
        Self::Standard
    }
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Standard => write!(f, "Standard address"),
            Self::Integrated(_) => write!(f, "Integrated address"),
            Self::SubAddress => write!(f, "Subaddress"),
        }
    }
}

fixed_hash::construct_fixed_hash! {
    /// Payment Id for integrated address
    pub struct PaymentId(8);
}

/// A generic Monero address
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub struct Address {
    /// The network on which the address is valid
    pub network: Network,
    /// The address type
    pub addr_type: AddressType,
    /// The address spend public key
    pub public_spend: PublicKey,
    /// The address view public key
    pub public_view: PublicKey,
}

impl Address {
    /// Create a standard address which is valid on the given network
    #[must_use]
    pub const fn standard(
        network: Network,
        public_spend: PublicKey,
        public_view: PublicKey,
    ) -> Self {
        Self {
            network,
            addr_type: AddressType::Standard,
            public_spend,
            public_view,
        }
    }

    /// Create a sub-address which is valid on the given network
    #[must_use]
    pub const fn subaddress(
        network: Network,
        public_spend: PublicKey,
        public_view: PublicKey,
    ) -> Self {
        Self {
            network,
            addr_type: AddressType::SubAddress,
            public_spend,
            public_view,
        }
    }

    /// Create an address with an integrated payment id which is valid on the given network
    #[must_use]
    pub fn integrated(
        network: Network,
        public_spend: PublicKey,
        public_view: PublicKey,
        payment_id: PaymentId,
    ) -> Self {
        Self {
            network,
            addr_type: AddressType::Integrated(payment_id),
            public_spend,
            public_view,
        }
    }

    /// Create a standard address from a view pair which is valid on the given network
    #[must_use]
    pub fn from_viewpair(network: Network, keys: &ViewPair) -> Self {
        let public_view = PublicKey::from_private_key(&keys.view);
        Self {
            network,
            addr_type: AddressType::Standard,
            public_spend: keys.spend,
            public_view,
        }
    }

    /// Create a standard address from a key pair which is valid on the given network
    #[must_use]
    pub fn from_keypair(network: Network, keys: &KeyPair) -> Self {
        let public_spend = PublicKey::from_private_key(&keys.spend);
        let public_view = PublicKey::from_private_key(&keys.view);
        Self {
            network,
            addr_type: AddressType::Standard,
            public_spend,
            public_view,
        }
    }

    /// Parse an address from a vector of bytes, fail if the magic byte is incorrect, if public
    /// keys are not valid points, if payment id is invalid, and if checksums missmatch
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let network = Network::from_u8(bytes[0])?;
        let addr_type = AddressType::from_slice(bytes, network)?;
        let public_spend =
            PublicKey::from_slice(&bytes[1..33]).map_err(|_| Error::InvalidFormat)?;
        let public_view =
            PublicKey::from_slice(&bytes[33..65]).map_err(|_| Error::InvalidFormat)?;

        let mut verify_checksum = [0_u8; 32];
        let (checksum_bytes, checksum) = match addr_type {
            AddressType::Standard | AddressType::SubAddress => (&bytes[0..65], &bytes[65..69]),
            AddressType::Integrated(_) => (&bytes[0..73], &bytes[73..77]),
        };
        keccak_256(checksum_bytes, &mut verify_checksum);
        if &verify_checksum[0..4] != checksum {
            return Err(Error::InvalidChecksum);
        }

        Ok(Self {
            network,
            addr_type,
            public_spend,
            public_view,
        })
    }

    /// Serialize the address as a vector of bytes
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.network.as_u8(&self.addr_type)];
        bytes.extend_from_slice(self.public_spend.as_bytes());
        bytes.extend_from_slice(self.public_view.as_bytes());
        if let AddressType::Integrated(payment_id) = &self.addr_type {
            bytes.extend_from_slice(&payment_id.0);
        }

        let mut checksum = [0_u8; 32];
        keccak_256(bytes.as_slice(), &mut checksum);
        bytes.extend_from_slice(&checksum[0..4]);
        bytes
    }

    /// Serialize the address as an hexadecimal string
    #[must_use]
    pub fn as_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", base58::encode(self.as_bytes().as_slice()).unwrap())
    }
}

impl FromStr for Address {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&base58::decode(s)?)
    }
}

#[cfg(any(feature = "serde", feature = "serde_support"))]
mod serde_impl {
    use super::*;

    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for Address {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&self.to_string())
        }
    }

    impl<'de> Deserialize<'de> for Address {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Address::from_str(&s).map_err(D::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{base58, Address, Network, PaymentId, PublicKey};

    #[test]
    fn deserialize_address() {
        let pub_spend = PublicKey::from_slice(&[
            226, 187, 17, 117, 6, 188, 105, 177, 58, 207, 205, 42, 205, 229, 251, 129, 118, 253,
            21, 245, 49, 67, 36, 75, 62, 12, 80, 90, 244, 194, 108, 210,
        ])
        .unwrap();
        let pub_view = PublicKey::from_slice(&[
            220, 115, 195, 55, 189, 88, 136, 78, 63, 32, 41, 33, 168, 205, 245, 3, 139, 234, 109,
            64, 198, 179, 53, 108, 247, 77, 183, 25, 172, 59, 113, 115,
        ])
        .unwrap();

        let address = "4ADT1BtbxqEWeMKp9GgPr2NeyJXXtNxvoDawpyA4WpzFcGcoHUvXeijE66DNfohE9r1bQYaBiQjEtKE7CtkTdLwiDznFzra";
        let add = Address::from_str(address);
        assert_eq!(
            Ok(Address::standard(Network::Mainnet, pub_spend, pub_view)),
            add
        );

        let bytes = base58::decode(address).unwrap();
        let add = Address::from_bytes(&bytes);
        assert_eq!(
            Ok(Address::standard(Network::Mainnet, pub_spend, pub_view)),
            add
        );
    }

    #[test]
    fn deserialize_integrated_address() {
        let pub_spend = PublicKey::from_slice(&[
            17, 81, 127, 230, 166, 35, 81, 36, 161, 94, 154, 206, 60, 98, 195, 62, 12, 11, 234,
            133, 228, 196, 77, 3, 68, 188, 84, 78, 94, 109, 238, 44,
        ])
        .unwrap();
        let pub_view = PublicKey::from_slice(&[
            115, 212, 211, 204, 198, 30, 73, 70, 235, 52, 160, 200, 39, 215, 134, 239, 249, 129,
            47, 156, 14, 116, 18, 191, 112, 207, 139, 208, 54, 59, 92, 115,
        ])
        .unwrap();
        let payment_id = PaymentId([88, 118, 184, 183, 41, 150, 255, 151]);

        let address = "4Byr22j9M2878Mtyb3fEPcBNwBZf5EXqn1Yi6VzR46618SFBrYysab2Cs1474CVDbsh94AJq7vuV3Z2DRq4zLcY3LHzo1Nbv3d8J6VhvCV";
        let add = Address::from_str(address);
        assert_eq!(
            Ok(Address::integrated(
                Network::Mainnet,
                pub_spend,
                pub_view,
                payment_id
            )),
            add
        );
    }

    #[test]
    fn deserialize_sub_address() {
        let pub_spend = PublicKey::from_slice(&[
            212, 104, 103, 28, 131, 98, 226, 228, 37, 244, 133, 145, 213, 157, 184, 232, 6, 146,
            127, 69, 187, 95, 33, 143, 9, 102, 181, 189, 230, 223, 231, 7,
        ])
        .unwrap();
        let pub_view = PublicKey::from_slice(&[
            154, 155, 57, 25, 23, 70, 165, 134, 222, 126, 85, 60, 127, 96, 21, 243, 108, 152, 150,
            87, 66, 59, 161, 121, 206, 130, 170, 233, 69, 102, 128, 103,
        ])
        .unwrap();

        let address = "8AW7SotwFrqfAKnibspuuhfowW4g3asvpQvdrTmPcpNr2GmXPtBBSxUPZQATAt8Vw2hiX9GDyxB4tMNgHjwt8qYsCeFDVvn";
        let add = Address::from_str(address);
        assert_eq!(
            Ok(Address::subaddress(Network::Mainnet, pub_spend, pub_view)),
            add
        );
    }

    #[test]
    fn serialize_address() {
        let address = "4ADT1BtbxqEWeMKp9GgPr2NeyJXXtNxvoDawpyA4WpzFcGcoHUvXeijE66DNfohE9r1bQYaBiQjEtKE7CtkTdLwiDznFzra";
        let add = Address::from_str(address).unwrap();
        let bytes = base58::decode(address).unwrap();
        assert_eq!(bytes, add.as_bytes());
    }

    #[test]
    fn serialize_integrated_address() {
        let address = "4Byr22j9M2878Mtyb3fEPcBNwBZf5EXqn1Yi6VzR46618SFBrYysab2Cs1474CVDbsh94AJq7vuV3Z2DRq4zLcY3LHzo1Nbv3d8J6VhvCV";
        let add = Address::from_str(address).unwrap();
        let bytes = base58::decode(address).unwrap();
        assert_eq!(bytes, add.as_bytes());
    }

    #[test]
    fn serialize_to_string() {
        let address = "4Byr22j9M2878Mtyb3fEPcBNwBZf5EXqn1Yi6VzR46618SFBrYysab2Cs1474CVDbsh94AJq7vuV3Z2DRq4zLcY3LHzo1Nbv3d8J6VhvCV";
        let add = Address::from_str(address).unwrap();
        assert_eq!(address, add.to_string());
    }
}
