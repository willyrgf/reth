// #![allow(dead_code)]

// use std::sync::mpsc::RecvError;
// use revm::db::DatabaseRef;
// use reth_primitives::StorageEntry;
// use std::sync::mpsc::{Receiver, Sender};
// use revm::{DatabaseCommit};
// use revm::{Bytecode, Database, KECCAK_EMPTY};
// use revm::{Account, AccountInfo, Log};

// use hashbrown::{hash_map::Entry, HashMap as Map};
// use reth_primitives::{
//     Address, H256, U256, H160,
// };

// /// Memory backend, storing all state values in a `Map` in memory.
// #[derive(Debug)]
// pub(crate) struct PipelinedCacheDB {
//     /// Account info where None means it is not existing. Not existing state is needed for Pre TANGERINE forks.
//     /// `code` is always `None`, and bytecode can be found in `contracts`.
//     pub(crate) accounts: Map<H160, DbAccount>,
//     /// Contracts in the cache
//     pub(crate) contracts: Map<H256, Bytecode>,
//     /// Logs in the cache
//     pub(crate) logs: Vec<Log>,
//     /// Block hashes in the cache
//     pub(crate) block_hashes: Map<U256, H256>,
//     /// A sender for requesting data from the database (likely in another thread)
//     pub(crate) db_requestor: Sender<DatabaseRequest>,
//     /// A receiver for receiving data from the database (likely from another thread)
//     pub(crate) db_receiver: Receiver<DatabaseResponse>,
// }

// #[derive(Debug, Clone, Default)]
// pub(crate) struct DbAccount {
//     pub(crate) info: AccountInfo,
//     /// If account is selfdestructed or newly created, storage will be cleared.
//     pub(crate) account_state: AccountState,
//     /// storage slots
//     pub(crate) storage: Map<U256, U256>,
// }

// impl DbAccount {
//     pub(crate) fn new_not_existing() -> Self {
//         Self {
//             account_state: AccountState::NotExisting,
//             ..Default::default()
//         }
//     }
//     pub(crate) fn info(&self) -> Option<AccountInfo> {
//         if matches!(self.account_state, AccountState::NotExisting) {
//             None
//         } else {
//             Some(self.info.clone())
//         }
//     }
// }

// impl From<Option<AccountInfo>> for DbAccount {
//     fn from(from: Option<AccountInfo>) -> Self {
//         if let Some(info) = from {
//             Self {
//                 info,
//                 account_state: AccountState::None,
//                 ..Default::default()
//             }
//         } else {
//             Self::new_not_existing()
//         }
//     }
// }

// impl From<AccountInfo> for DbAccount {
//     fn from(info: AccountInfo) -> Self {
//         Self {
//             info,
//             account_state: AccountState::None,
//             ..Default::default()
//         }
//     }
// }

// #[derive(Debug, Clone, Default)]
// pub(crate) enum AccountState {
//     /// Before Spurious Dragon hardfork there were a difference between empty and not existing.
//     /// And we are flaging it here.
//     NotExisting,
//     /// EVM touched this account. For newer hardfork this means it can be clearead/removed from state.
//     Touched,
//     /// EVM cleared storage of this account, mostly by selfdestruct, we dont ask database for storage slots
//     /// and asume they are U256::ZERO
//     StorageCleared,
//     /// EVM didnt interacted with this account
//     #[default]
//     None,
// }







// // pub(crate) enum DatabaseRequest {
// //     Basic(Address),
// //     Storage(Address, H256),
// //     BlockHash(U256),
// // }

// // #[derive(Debug)]
// // pub(crate) enum DatabaseResponse {
// //     Basic(Address, Option<AccountInfo>),
// //     Storage(Address, Option<(U256, U256)>),
// //     BlockHash(U256, Option<H256>),
// // }

// // impl PipelinedCacheDB {
// //     pub(crate) fn new(db_requestor: Sender<DatabaseRequest>, db_receiver: Receiver<DatabaseResponse>) -> Self {
// //         let mut contracts = Map::new();
// //         contracts.insert(KECCAK_EMPTY, Bytecode::new());
// //         contracts.insert(H256::zero(), Bytecode::new());
// //         Self {
// //             accounts: Map::new(),
// //             contracts,
// //             logs: Vec::default(),
// //             block_hashes: Map::new(),
// //             db_requestor,
// //             db_receiver,
// //         }
// //     }

// //     pub(crate) fn insert_contract(&mut self, account: &mut AccountInfo) {
// //         if let Some(code) = &account.code {
// //             if !code.is_empty() {
// //                 account.code_hash = code.hash();
// //                 self.contracts
// //                     .entry(account.code_hash)
// //                     .or_insert_with(|| code.clone());
// //             }
// //         }
// //         if account.code_hash.is_zero() {
// //             account.code_hash = KECCAK_EMPTY;
// //         }
// //     }

// //     /// Insert account info but not override storage
// //     pub(crate) fn insert_account_info(&mut self, address: H160, mut info: AccountInfo) {
// //         self.insert_contract(&mut info);
// //         self.accounts.entry(address).or_default().info = info;
// //     }

// //     fn basic_process_or_req(&mut self, address: H160) -> Result<&mut DbAccount, RecvError> {
// //         let mut channel_iter = self.db_receiver.try_iter();
// //         // empty out channel until empty or found matching request
// //         while let Some(db_resp) = channel_iter.next() {
// //             match db_resp {
// //                 DatabaseResponse::Basic(db_addr, Some(db_info)) => {
// //                     if db_addr == address {
// //                         // matching request
// //                         match self.accounts.entry(address) {
// //                             Entry::Vacant(entry) => {
// //                                 return Ok(entry.insert(DbAccount {
// //                                     info: db_info,
// //                                     ..Default::default()
// //                                 }))
// //                             }
// //                             _ => unreachable!()
// //                         }
// //                     } else {
// //                         self.accounts.entry(db_addr).or_default().info = db_info;
// //                     }
// //                 }
// //                 DatabaseResponse::Storage(db_addr, Some((key, value))) => {
// //                     match self.accounts.entry(db_addr) {
// //                         Entry::Occupied(entry) => {
// //                             entry.into_mut().storage.insert(key, value);
// //                         }
// //                         Entry::Vacant(entry) => {
// //                             let entry = entry.insert(DbAccount::new_not_existing());
// //                             entry.storage.insert(key, value);
// //                         }
// //                     }
// //                 }
// //                 _ => panic!("Bad channel info")
// //             }
// //         }
// //         self.request_basic_or_insert_default(address)
// //     }

// //     pub(crate) fn request_basic_or_insert_default(&mut self, address: H160) -> Result<&mut DbAccount, RecvError> {
// //         self.db_requestor.send(DatabaseRequest::Basic(address)).expect("BAD SEND");
// //         match self.db_receiver.recv()? {
// //             DatabaseResponse::Basic(db_addr, db_info) => {
// //                 assert_eq!(db_addr, address);
// //                 match db_info {
// //                     Some(db_info) => {
// //                         match self.accounts.entry(address) {
// //                             Entry::Vacant(entry) => {
// //                                 return Ok(entry.insert(DbAccount {
// //                                     info: db_info,
// //                                     ..Default::default()
// //                                 }))
// //                             }
// //                             _ => unreachable!()
// //                         }
// //                     }
// //                     _ => {
// //                         match self.accounts.entry(address) {
// //                             Entry::Vacant(entry) => {
// //                                 Ok(entry.insert(DbAccount::new_not_existing()))
// //                             }
// //                             _ => unreachable!()
// //                         }
// //                     }
// //                 }
                
// //             }
// //             e => panic!("Got unexpected response from db: {:?}", e),
// //         }
// //     }

// //     fn load_account(&mut self, address: H160) -> Result<&mut DbAccount, RecvError> {
// //         if self.accounts.contains_key(&address) {
// //             match self.accounts.entry(address) {
// //                 Entry::Occupied(entry) => Ok(entry.into_mut()),
// //                 _ => unreachable!()
// //             }
// //         } else {
// //             // process the channel until we match or finish all pending items
// //             self.basic_process_or_req(address)
// //         }
// //     }

// //     /// insert account storage without overriding account info
// //     pub(crate) fn insert_account_storage(
// //         &mut self,
// //         address: H160,
// //         slot: U256,
// //         value: U256,
// //     ) -> Result<(), RecvError> {
// //         let account = self.load_account(address)?;
// //         account.storage.insert(slot, value);
// //         Ok(())
// //     }

// //     /// replace account storage without overriding account info
// //     pub(crate) fn replace_account_storage(
// //         &mut self,
// //         address: H160,
// //         storage: Map<U256, U256>,
// //     ) -> Result<(), RecvError> {
// //         let account = self.load_account(address)?;
// //         account.account_state = AccountState::StorageCleared;
// //         account.storage = storage.into_iter().collect();
// //         Ok(())
// //     }
// // }

// // impl DatabaseCommit for PipelinedCacheDB {
// //     fn commit(&mut self, changes: Map<H160, Account>) {
// //         for (address, mut account) in changes {
// //             if account.is_destroyed {
// //                 let db_account = self.accounts.entry(address).or_default();
// //                 db_account.storage.clear();
// //                 db_account.account_state = AccountState::NotExisting;
// //                 db_account.info = AccountInfo::default();
// //                 continue;
// //             }
// //             self.insert_contract(&mut account.info);

// //             let db_account = self.accounts.entry(address).or_default();
// //             db_account.info = account.info;

// //             db_account.account_state = if account.storage_cleared {
// //                 db_account.storage.clear();
// //                 AccountState::StorageCleared
// //             } else {
// //                 AccountState::Touched
// //             };
// //             db_account.storage.extend(
// //                 account
// //                     .storage
// //                     .into_iter()
// //                     .map(|(key, value)| (key, value.present_value())),
// //             );
// //         }
// //     }
// // }

// // impl Database for PipelinedCacheDB {
// //     type Error = RecvError;

// //     fn block_hash(&mut self, number: U256) -> Result<H256, Self::Error> {
// //         match self.block_hashes.entry(number) {
// //             Entry::Occupied(entry) => Ok(*entry.get()),
// //             Entry::Vacant(entry) => {
// //                 // let hash = self.db.block_hash(number)?;
// //                 // entry.insert(hash);
// //                 // Ok(hash)
// //                 Ok(Default::default())
// //             }
// //         }
// //     }

// //     fn basic(&mut self, address: H160) -> Result<Option<AccountInfo>, Self::Error> {
// //         let basic = match self.accounts.entry(address) {
// //             Entry::Occupied(entry) => entry.into_mut(),
// //             Entry::Vacant(entry) => self.basic_process_or_req(address)?,
// //         };
// //         Ok(basic.info())
// //     }

// //     /// Get the value in an account's storage slot.
// //     ///
// //     /// It is assumed that account is already loaded.
// //     fn storage(&mut self, address: H160, index: U256) -> Result<U256, Self::Error> {
// //         // match self.accounts.entry(address) {
// //         //     Entry::Occupied(mut acc_entry) => {
// //         //         let acc_entry = acc_entry.get_mut();
// //         //         match acc_entry.storage.entry(index) {
// //         //             Entry::Occupied(entry) => Ok(*entry.get()),
// //         //             Entry::Vacant(entry) => {
// //         //                 if matches!(
// //         //                     acc_entry.account_state,
// //         //                     AccountState::StorageCleared | AccountState::NotExisting
// //         //                 ) {
// //         //                     Ok(U256::ZERO)
// //         //                 } else {
// //         //                     let slot = self.db.storage(address, index)?;
// //         //                     entry.insert(slot);
// //         //                     Ok(slot)
// //         //                 }
// //         //             }
// //         //         }
// //         //     }
// //         //     Entry::Vacant(acc_entry) => {
// //         //         // acc needs to be loaded for us to access slots.
// //         //         let info = self.db.basic(address)?;
// //         //         let (account, value) = if info.is_some() {
// //         //             let value = self.db.storage(address, index)?;
// //         //             let mut account: DbAccount = info.into();
// //         //             account.storage.insert(index, value);
// //         //             (account, value)
// //         //         } else {
// //         //             (info.into(), U256::ZERO)
// //         //         };
// //         //         acc_entry.insert(account);
// //         //         Ok(value)
// //         //     }
// //         // }
// //         Err(RecvError)
// //     }

// //     fn code_by_hash(&mut self, code_hash: H256) -> Result<Bytecode, Self::Error> {
// //         match self.contracts.entry(code_hash) {
// //             Entry::Occupied(entry) => Ok(entry.get().clone()),
// //             Entry::Vacant(entry) => {
// //                 Err(RecvError)
// //                 // if you return code bytes when basic fn is called this function is not needed.
// //                 // Ok(entry.insert(self.db.code_by_hash(code_hash)?).clone())
// //             }
// //         }
// //     }
// // }

// // // impl DatabaseRef for PipelinedCacheDB {
// // //     type Error = ExtDB::Error;

// // //     fn basic(&self, address: H160) -> Result<Option<AccountInfo>, Self::Error> {
// // //         match self.accounts.get(&address) {
// // //             Some(acc) => Ok(acc.info()),
// // //             None => self.db.basic(address),
// // //         }
// // //     }

// // //     fn storage(&self, address: H160, index: U256) -> Result<U256, Self::Error> {
// // //         match self.accounts.get(&address) {
// // //             Some(acc_entry) => match acc_entry.storage.get(&index) {
// // //                 Some(entry) => Ok(*entry),
// // //                 None => {
// // //                     if matches!(
// // //                         acc_entry.account_state,
// // //                         AccountState::StorageCleared | AccountState::NotExisting
// // //                     ) {
// // //                         Ok(U256::ZERO)
// // //                     } else {
// // //                         self.db.storage(address, index)
// // //                     }
// // //                 }
// // //             },
// // //             None => self.db.storage(address, index),
// // //         }
// // //     }

// // //     fn code_by_hash(&self, code_hash: H256) -> Result<Bytecode, Self::Error> {
// // //         match self.contracts.get(&code_hash) {
// // //             Some(entry) => Ok(entry.clone()),
// // //             None => self.db.code_by_hash(code_hash),
// // //         }
// // //     }

// // //     fn block_hash(&self, number: U256) -> Result<H256, Self::Error> {
// // //         match self.block_hashes.get(&number) {
// // //             Some(entry) => Ok(*entry),
// // //             None => self.db.block_hash(number),
// // //         }
// // //     }
// // // }