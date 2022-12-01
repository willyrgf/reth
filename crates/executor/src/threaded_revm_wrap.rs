#![allow(unused_imports, unreachable_pub, missing_docs)]
//! Provider that wraps around database traits.
//! to provide higher level abstraction over database tables.

use reth_interfaces::provider::{
    db_provider::{StateProviderImplHistory, StateProviderImplLatest},
    threaded_db_requestor::{
        CacheAccountProvider, CacheStateProvider, DatabaseRequest, DatabaseResponse,
        ThreadedChannelAccountProvider, ThreadedChannelAccountRequestor, ThreadedChannelRequestor,
        ThreadedChannelStateProvider, ThreadedChannelStateRequestor, MAX_PREFETCH,
    },
};

use reth_interfaces::{
    db::{tables, Database, DatabaseGAT, DbTx},
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
    pub accounts: Map<Address, DbAccount>,
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

#[derive(Debug, Clone, Default, Copy)]
pub struct DbAccount {
    pub account: Account,
    pub state: AccountState,
}

#[derive(Debug, Clone, Default, Copy)]
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
                acct.account = maybe_acct.unwrap_or_default();
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
        match self.accounts.get(&address) {
            Some(acct) => Some(acct.account),
            _ => None
        }
    }
}

/// Function needed for executor.
impl CacheStateProvider for ThreadedCacheDB {
    /// Get storage.
    fn storage(&self, account: Address, storage_key: StorageKey) -> Option<StorageValue> {
        // TODO(brockelmore): reorg data structures to remove the `self.accounts.get()`
        if let Some(storage_map) = self.storage.get(&account) {
            match storage_map.get(&storage_key) {
                Some(val) => Some(*val),
                None => {
                    if matches!(
                        self.accounts.get(&account).expect("storage but no account").state,
                        AccountState::StorageCleared | AccountState::NotExisting
                    ) {
                        Some(U256::zero())
                    } else {
                        None
                    }
                }
            }
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
    type Error = reth_interfaces::Error;

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

    use crate::threaded_revm_wrap::ThreadedCacheDB;
    use reth_interfaces::{
        db::{tables::PlainAccountState, Database, DbTxMut},
        provider::{
            threaded_db_provider::BasicThreadedDB, threaded_db_requestor::DatabaseResponse,
            threaded_db_responder::ThreadedChannelDB, AccountProvider, StateProviderFactory,
        },
    };
    use reth_primitives::{Account, Address, H256, U256};
    use revm::Database as REVMDatabase;
    use std::{str::FromStr, sync::Mutex};
    use tempfile::TempDir;

    use std::sync::Arc;

    use reth_db::mdbx::WriteMap;

    use std::sync::mpsc::channel;

    fn threaded_setup() -> (ThreadedCacheDB, BasicThreadedDB<reth_db::kv::Env<WriteMap>>) {
        let path = TempDir::new().expect(reth_db::kv::test_utils::ERROR_TEMPDIR).into_path();
        let db = Arc::new(reth_db::kv::test_utils::create_test_db_with_path::<WriteMap>(
            reth_db::kv::EnvKind::RW,
            &path,
        ));
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

        (cachedb, db_handle)
    }

    #[test]
    fn sanity_loader() {
        let (mut cachedb, mut db_handle) = threaded_setup();

        let value = Account {
            nonce: 18446744073709551615,
            bytecode_hash: Some(H256::random()),
            balance: U256::max_value(),
        };

        let key =
            Address::from_str("0xa2c122be93b0074270ebee7f6b7292c7deb45047").expect("BAD PARSE");

        {
            // PUT
            let result = db_handle.db.update(|tx| {
                tx.put::<PlainAccountState>(key, value).expect("BAD PUT");
                200
            });
            assert!(result.expect("BAD RETURN") == 200);
        }

        let _handler = std::thread::spawn(move || {
            if let Err(e) = db_handle.run() {
                panic!("db panicked: {:?}", e);
            }
        });

        let a = cachedb.basic(key).unwrap().unwrap();
        assert!(a.balance == value.balance);
        assert!(a.nonce == value.nonce);
        assert!(a.code_hash == value.bytecode_hash.unwrap());
    }

    #[test]
    fn out_of_order_processes_channel() {
        let (mut cachedb, mut db_handle) = threaded_setup();

        let value = Account {
            nonce: 18446744073709551615,
            bytecode_hash: Some(H256::random()),
            balance: U256::max_value(),
        };

        let value2 =
            Account { nonce: 1, bytecode_hash: Some(H256::random()), balance: U256::zero() };

        let key =
            Address::from_str("0xa2c122be93b0074270ebee7f6b7292c7deb45047").expect("BAD PARSE");

        let key2 =
            Address::from_str("0xb2c122be93b0074270ebee7f6b7292c7deb45048").expect("BAD PARSE");

        {
            // PUT
            let result = db_handle.db.update(|tx| {
                tx.put::<PlainAccountState>(key, value).expect("BAD PUT");
                200
            });
            assert!(result.expect("BAD RETURN") == 200);

            let result = db_handle.db.update(|tx| {
                tx.put::<PlainAccountState>(key2, value2).expect("BAD PUT");
                200
            });
            assert!(result.expect("BAD RETURN") == 200);
        }

        // send a supurious response to the requestor without them asking for it
        {
            let response_sender = db_handle.response_sender();
            let response_sender = response_sender.lock().unwrap();
            let basic = db_handle.latest().unwrap().basic_account(key2);
            match basic {
                Ok(maybe_db_acct_info) => {
                    response_sender.send(DatabaseResponse::Basic(key2, maybe_db_acct_info)).unwrap()
                }
                Err(_e) => {}
            }
        }

        // run the db indefinitely
        let _handler = std::thread::spawn(move || {
            if let Err(e) = db_handle.run() {
                panic!("db panicked: {:?}", e);
            }
        });

        // ask for the first account's info, this should send a request to the db_handle
        let a = cachedb.basic(key).unwrap().unwrap();
        assert!(a.balance == value.balance);
        assert!(a.nonce == value.nonce);
        assert!(a.code_hash == value.bytecode_hash.unwrap());
        // as for the second account's info, this *should'nt* send a request to the db handle and
        // should have been cached when we processed it
        let b = cachedb.basic(key2).unwrap().unwrap();
        assert!(b.balance == value2.balance);
        assert!(b.nonce == value2.nonce);
        assert!(b.code_hash == value2.bytecode_hash.unwrap());
    }
}
