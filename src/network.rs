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

//! Monero network types
//!
//! This module defines the different Monero networks and their magic bytes.

use crate::util::address::AddressType;
use std::{error, fmt};

/// Network error types
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid magic network byte
    InvalidMagicByte,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::InvalidMagicByte => "invalid magic byte",
            }
        )
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match self {
            Self::InvalidMagicByte => None,
        }
    }
}

/// Network type
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Network {
    /// Monero Mainnet
    Mainnet,
    /// Monero Stagenet
    Stagenet,
    /// Monero Testnet
    Testnet,
}

impl Network {
    /// Get the associated magic byte given an address type
    ///
    /// **Same as** [`monero/src/cryptonote_config.h`](https://github.com/monero-project/monero/blob/159c78758af0a0af9df9a4f9ab81888f9322e9be/src/cryptonote_config.h#L190-L239)
    #[must_use]
    pub fn as_u8(self, addr_type: &AddressType) -> u8 {
        use AddressType::*;
        use Network::*;
        match self {
            Mainnet => match addr_type {
                Standard => 18,
                Integrated(_) => 19,
                SubAddress => 42,
            },
            Testnet => match addr_type {
                Standard => 53,
                Integrated(_) => 54,
                SubAddress => 63,
            },
            Stagenet => match addr_type {
                Standard => 24,
                Integrated(_) => 25,
                SubAddress => 36,
            },
        }
    }

    /// Recover the network type given an address magic byte
    ///
    /// **Same as** [`monero/src/cryptonote_config.h`](https://github.com/monero-project/monero/blob/159c78758af0a0af9df9a4f9ab81888f9322e9be/src/cryptonote_config.h#L190-L239)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        use Network::*;
        match byte {
            18 | 19 | 42 => Ok(Mainnet),
            53 | 54 | 63 => Ok(Testnet),
            24 | 25 | 36 => Ok(Stagenet),
            _ => Err(Error::InvalidMagicByte),
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Self::Mainnet
    }
}
