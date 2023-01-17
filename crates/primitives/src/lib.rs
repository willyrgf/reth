#![warn(missing_debug_implementations, missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]

//! Commonly used types in reth.
//!
//! This crate contains Ethereum primitive types and helper functions.

mod account;
mod bits;
mod block;
pub mod bloom;
mod chain;
mod chain_spec;
mod constants;
mod error;
mod forkid;
mod genesis;
mod hardfork;
mod header;
mod hex_bytes;
mod integer_list;
mod jsonu256;
mod log;
mod net;
mod peer;
mod receipt;
mod storage;
mod transaction;

/// Helper function for calculating Merkle proofs and hashes
pub mod proofs;

pub use account::Account;
pub use bits::H512;
pub use block::{Block, BlockHashOrNumber, SealedBlock};
pub use bloom::Bloom;
pub use chain::Chain;
pub use chain_spec::{ChainSpec, ChainSpecBuilder, ParisStatus, GOERLI, MAINNET, SEPOLIA};
pub use constants::{EMPTY_OMMER_ROOT, KECCAK_EMPTY, MAINNET_GENESIS};
pub use forkid::{ForkFilter, ForkHash, ForkId, ForkTransition, ValidationError};
pub use genesis::{Genesis, GenesisAccount};
pub use hardfork::Hardfork;
pub use header::{Header, HeadersDirection, SealedHeader};
pub use hex_bytes::Bytes;
pub use integer_list::IntegerList;
pub use jsonu256::JsonU256;
pub use log::Log;
pub use net::NodeRecord;
pub use peer::{PeerId, WithPeerId};
pub use receipt::Receipt;
pub use storage::StorageEntry;
pub use transaction::{
    AccessList, AccessListItem, FromRecoveredTransaction, IntoRecoveredTransaction, Signature,
    Transaction, TransactionKind, TransactionSigned, TransactionSignedEcRecovered, TxEip1559,
    TxEip2930, TxLegacy, TxType,
};

/// A block hash.
pub type BlockHash = H256;
/// A block number.
pub type BlockNumber = u64;
/// An Ethereum address.
pub type Address = H160;
// TODO(onbjerg): Is this not the same as [BlockHash]?
/// BlockId is Keccak hash of the header
pub type BlockID = H256;
/// A transaction hash is a kecack hash of an RLP encoded signed transaction.
pub type TxHash = H256;
/// The sequence number of all existing transactions.
pub type TxNumber = u64;
/// Chain identifier type (introduced in EIP-155).
pub type ChainId = u64;
/// An account storage key.
pub type StorageKey = H256;
/// An account storage value.
pub type StorageValue = U256;
/// The ID of block/transaction transition (represents state transition)
pub type TransitionId = u64;

pub use ethers_core::{
    types as rpc,
    types::{BigEndianHash, H128, H64, U64},
};
pub use revm_interpreter::{ruint::aliases::U128, B160 as H160, B256 as H256, U256};

#[doc(hidden)]
mod __reexport {
    pub use hex;
    pub use hex_literal;
    pub use tiny_keccak;
}

/// Various utilities
pub mod utils {
    pub use ethers_core::types::serde_helpers;
}

// Useful reexports
pub use __reexport::*;

/// Returns the keccak256 hash for the given data.
#[inline]
pub fn keccak256(data: impl AsRef<[u8]>) -> H256 {
    use tiny_keccak::{Hasher, Keccak};

    let mut buf = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data.as_ref());
    hasher.finalize(&mut buf);
    buf.into()
}
