#![allow(unused_imports, unreachable_pub, missing_docs)]
//! Provider that wraps around database traits.
//! to provide higher level abstraction over database tables.

use crate::provider::{
    db_provider::{StateProviderImplHistory, StateProviderImplLatest},
    threaded_db_requestor::{
        CacheAccountProvider, CacheStateProvider, DatabaseRequest, DatabaseResponse,
        ThreadedChannelAccountProvider, ThreadedChannelAccountRequestor, ThreadedChannelRequestor,
        ThreadedChannelStateProvider, ThreadedChannelStateRequestor, MAX_PREFETCH,
    },
};

use crate::{
    db::{tables, Database, DatabaseGAT, DbTx},
    error::Error,
    provider::{Error as ProviderError, StateProviderFactory},
    Result,
};
use reth_primitives::{
    Account, Address, BlockHash, BlockNumber, Bytes, Log, StorageKey, StorageValue, H160, H256,
    KECCAK_EMPTY, U256,
};

use hashbrown::HashMap as Map;
use revm::{AccountInfo, Bytecode, Database as REVMDatabase};
use std::{
    collections::BTreeMap,
    sync::{
        mpsc::{Receiver, Sender},
        Arc, Mutex,
    },
};

#[derive(Debug, Clone)]
pub struct ThreadedCacheDB {
    pub accounts: Map<Address, Account>,
    pub storage: Map<Address, BTreeMap<StorageKey, StorageValue>>,
    pub contracts: Map<H256, Bytes>,
    pub logs: Vec<Log>,
    pub block_hashes: Map<U256, H256>,
    pub request_sender: Arc<Mutex<Sender<DatabaseRequest<MAX_PREFETCH>>>>,
    pub response_receiver: Arc<Mutex<Receiver<DatabaseResponse<MAX_PREFETCH>>>>,
}

impl ThreadedCacheDB {
    pub fn new(
        request_sender: Arc<Mutex<Sender<DatabaseRequest<MAX_PREFETCH>>>>,
        response_receiver: Arc<Mutex<Receiver<DatabaseResponse<MAX_PREFETCH>>>>,
    ) -> Self {
        Self {
            accounts: Default::default(),
            storage: Default::default(),
            contracts: Default::default(),
            logs: Default::default(),
            block_hashes: Default::default(),
            request_sender,
            response_receiver,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DbAccount {
    pub account: Account,
    pub state: AccountState,
}

#[derive(Debug, Clone, Default)]
pub enum AccountState {
    /// Before Spurious Dragon hardfork there were a difference between empty and not existing.
    /// And we are flaging it here.
    NotExisting,
    /// EVM touched this account. For newer hardfork this means it can be clearead/removed from
    /// state.
    Touched,
    /// EVM cleared storage of this account, mostly by selfdestruct, we dont ask database for
    /// storage slots and asume they are U256::ZERO
    StorageCleared,
    /// EVM didnt interacted with this account
    #[default]
    None,
}

impl ThreadedChannelAccountRequestor for ThreadedCacheDB {}
impl ThreadedChannelStateRequestor for ThreadedCacheDB {}
impl ThreadedChannelAccountProvider for ThreadedCacheDB {}
impl ThreadedChannelStateProvider for ThreadedCacheDB {}

impl ThreadedChannelRequestor for ThreadedCacheDB {
    fn request_sender(&mut self) -> Arc<Mutex<Sender<DatabaseRequest<MAX_PREFETCH>>>> {
        self.request_sender.clone()
    }
    fn response_receiver(&mut self) -> Arc<Mutex<Receiver<DatabaseResponse<MAX_PREFETCH>>>> {
        self.response_receiver.clone()
    }
    fn cache_response(&mut self, resp: DatabaseResponse<MAX_PREFETCH>) {
        match resp {
            DatabaseResponse::Basic(addr, maybe_acct) => {
                let acct = self.accounts.entry(addr).or_default();
                *acct = maybe_acct.unwrap_or_default();
            }
            DatabaseResponse::Storage(addr, (key, maybe_value)) => {
                let storage = self.storage.entry(addr).or_default();
                storage.insert(key, maybe_value.unwrap_or_default());
            }
            DatabaseResponse::BlockHash(num, maybe_hash) => {
                self.block_hashes.insert(num, maybe_hash.unwrap_or_default());
            }
            DatabaseResponse::BytecodeFromHash(hash, maybe_code) => {
                self.contracts.insert(hash, maybe_code.unwrap_or_default());
            }
            DatabaseResponse::MultiStorage(addr, vals) => {
                let storage = self.storage.entry(addr).or_default();
                vals.into_iter().for_each(|(key, val)| {
                    storage.insert(key, val.unwrap_or_default());
                });
            }
        }
    }
}

impl CacheAccountProvider for ThreadedCacheDB {
    fn basic_account(&self, address: Address) -> Option<Account> {
        self.accounts.get(&address).copied()
    }
}

/// Function needed for executor.
impl CacheStateProvider for ThreadedCacheDB {
    /// Get storage.
    fn storage(&self, account: Address, storage_key: StorageKey) -> Option<StorageValue> {
        if let Some(storage_map) = self.storage.get(&account) {
            storage_map.get(&storage_key).copied()
        } else {
            None
        }
    }

    /// Get account code by its hash
    fn bytecode_by_hash(&self, code_hash: H256) -> Option<Bytes> {
        self.contracts.get(&code_hash).cloned()
    }

    /// Get block hash by number.
    fn block_hash(&self, number: U256) -> Option<H256> {
        self.block_hashes.get(&number).copied()
    }
}

impl REVMDatabase for ThreadedCacheDB {
    type Error = Error;

    fn block_hash(&mut self, number: U256) -> std::result::Result<H256, Self::Error> {
        if let Some(hash) = ThreadedChannelStateProvider::block_hash(self, number)? {
            Ok(hash)
        } else {
            Ok(Default::default())
        }
    }

    fn basic(&mut self, address: H160) -> std::result::Result<Option<AccountInfo>, Self::Error> {
        if let Some(acct) = ThreadedChannelAccountProvider::basic_account(self, address)? {
            if let Some(code_hash) = acct.bytecode_hash {
                let code = self.code_by_hash(code_hash)?;
                Ok(Some(AccountInfo {
                    balance: acct.balance,
                    nonce: acct.nonce,
                    code_hash,
                    code: Some(code),
                }))
            } else {
                Ok(Some(AccountInfo {
                    balance: acct.balance,
                    nonce: acct.nonce,
                    code_hash: KECCAK_EMPTY,
                    code: None,
                }))
            }
        } else {
            Ok(None)
        }
    }

    /// Get the value in an account's storage slot.
    ///
    /// It is assumed that account is already loaded.
    fn storage(&mut self, address: H160, index: U256) -> std::result::Result<U256, Self::Error> {
        Ok(ThreadedChannelStateProvider::storage(self, address, index)?.unwrap_or_default())
    }

    fn code_by_hash(&mut self, code_hash: H256) -> std::result::Result<Bytecode, Self::Error> {
        let maybe_code = ThreadedChannelStateProvider::bytecode_by_hash(self, code_hash)?;
        Ok(Bytecode::new_raw(maybe_code.unwrap_or_default().0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::{tables, DBContainer, Database, DatabaseGAT, DbTx},
        error::Error,
        provider::{
            threaded_db_provider::BasicThreadedDB, Error as ProviderError, StateProviderFactory,
        },
        Result,
    };
    use reth_db::{kv::*, mdbx::WriteMap};
    use std::sync::mpsc::channel;
    use tempfile::TempDir;

    #[test]
    fn sanity_loader() {
        let path = TempDir::new().expect(test_utils::ERROR_TEMPDIR).into_path();
        let db = Arc::new(test_utils::create_test_db_with_path::<WriteMap>(EnvKind::RW, &path));
        let (request_sender, request_receiver) = channel();
        let (response_sender, response_receiver) = channel();

        let cachedb = ThreadedCacheDB::new(
            Arc::new(Mutex::new(request_sender)),
            Arc::new(Mutex::new(response_receiver)),
        );
        let db_handle = BasicThreadedDB::new(
            db,
            Arc::new(Mutex::new(request_receiver)),
            Arc::new(Mutex::new(response_sender)),
        );
    }
}
