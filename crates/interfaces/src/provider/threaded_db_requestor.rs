#![allow(dead_code, unreachable_pub, missing_docs)]
use std::sync::Mutex;
use std::sync::Arc;
use std::sync::mpsc::{Sender, Receiver};

use reth_primitives::{
    Address, H256, U256, StorageValue, StorageKey, Account, Bytes
};
use crate::Result;
use crate::provider::{Error as ProviderError};

pub const MAX_PREFETCH: usize = 4;

#[derive(Debug, Copy, Clone)]
pub enum DatabaseRequest<const MAX_MULTI: usize> {
    Basic(Address),
    Storage(Address, StorageKey),
    BlockHash(U256),
    BytecodeFromHash(H256),
    MultiStorage(Address, [StorageKey; MAX_MULTI]),
}

#[derive(Debug, Clone)]
pub enum DatabaseResponse<const MAX_MULTI: usize> {
    Basic(Address, Option<Account>),
    Storage(Address, (StorageKey, Option<StorageValue>)),
    BlockHash(U256, Option<H256>),
    BytecodeFromHash(H256, Option<Bytes>),
    MultiStorage(Address, [(StorageKey, Option<StorageValue>); MAX_MULTI]),
    // TODO(brockelmore): Create error variant here and handle it in the matches
}


/// Account provider
pub trait CacheAccountProvider: Send + Sync {
    /// Get basic account information.
    fn basic_account(&self, address: Address) -> Option<Account>;
}

/// Function needed for executor.
pub trait CacheStateProvider: CacheAccountProvider + Send + Sync {
    /// Get storage.
    fn storage(&self, account: Address, storage_key: StorageKey) -> Option<StorageValue>;

    /// Get account code by its hash
    fn bytecode_by_hash(&self, code_hash: H256) -> Option<Bytes>;

    /// Get block hash by number.
    fn block_hash(&self, number: U256) -> Option<H256>;
}

/// A trait for an executor that uses a threaded db that communicate over channels
pub trait ThreadedChannelRequestor {
	/// Gets the database request sender
	fn request_sender(&mut self) -> Arc<Mutex<Sender<DatabaseRequest<MAX_PREFETCH>>>>;
	/// Gets the database response receiver
	fn response_receiver(&mut self) -> Arc<Mutex<Receiver<DatabaseResponse<MAX_PREFETCH>>>>;
	/// Caches an out-of-order response or currently unneeded response. Realistically, this is just loading the data into the cache
	fn cache_response(&mut self, resp: DatabaseResponse<MAX_PREFETCH>);

	/// Gets the response from the receiver, and calls the associated match function.
	fn get_and_handle_response<T>(
		&mut self,
		request: DatabaseRequest<MAX_PREFETCH>,
		match_func: &dyn Fn(&mut Self, DatabaseResponse<MAX_PREFETCH>, DatabaseRequest<MAX_PREFETCH>) -> Result<Option<T>>
	) -> Result<Option<T>> {
		let receiver = self.response_receiver();
		let receiver = receiver.lock().unwrap();
		let resp = receiver.recv().map_err(|_e| ProviderError::BadChannelRecv)?;
		match_func(self, resp, request)
	}
}

/// Account provider via threaded db with communication over channels
pub trait ThreadedChannelAccountRequestor: ThreadedChannelRequestor + Send + Sync {
    /// Get basic account information.
    fn request_basic_account(&mut self, address: Address) -> Result<Option<Account>> {
    	let request = DatabaseRequest::Basic(address);
    	let sender = self.request_sender();
    	let sender = sender.lock().unwrap();
    	sender.send(request).map_err(|_e| ProviderError::BadChannelSend)?;
    	self.get_and_handle_response(request, &Self::match_basic)	
    }

    /// Takes an arbitrary response and a storage request, checks if the response matches. If it doesn't, it handles the out-of-order response
    /// and looks for the next response
    fn match_basic(&mut self, resp: DatabaseResponse<MAX_PREFETCH>, request: DatabaseRequest<MAX_PREFETCH>) -> Result<Option<Account>> {
		match resp {
    		DatabaseResponse::Basic(db_addr, maybe_db_acct_info) => {
    			// check that this response is the one we were expecting
    			match request {
    				DatabaseRequest::Basic(addr) => {
    					if addr == db_addr {
    						// the request and response match, return it
    						Ok(maybe_db_acct_info)
    					} else {
    						// it doesnt match
    						self.cache_response(DatabaseResponse::Basic(db_addr, maybe_db_acct_info));
			    			self.get_and_handle_response(request, &Self::match_basic)
    					}
    				}
    				_ => unreachable!()
    			}
    		}
    		other => {
    			self.cache_response(other);
    			self.get_and_handle_response(request, &Self::match_basic)
    		}
    	}
	}
}

/// Function needed for executor.
pub trait ThreadedChannelStateRequestor: ThreadedChannelRequestor + ThreadedChannelAccountRequestor + Send + Sync {
    /// Request and get storage from threaded DB via channels.
    fn request_storage(&mut self, account: Address, storage_key: StorageKey) -> Result<Option<StorageValue>> {
    	let request = DatabaseRequest::Storage(account, storage_key);
    	let sender = self.request_sender();
    	let sender = sender.lock().unwrap();
    	sender.send(request).map_err(|_e| ProviderError::BadChannelSend)?;
    	self.get_and_handle_response(request, &Self::match_storage)
    }

    /// Get account code by its hash from threaded DB via channels.
    fn request_bytecode_by_hash(&mut self, code_hash: H256) -> Result<Option<Bytes>> {
    	let request = DatabaseRequest::BytecodeFromHash(code_hash);
    	let sender = self.request_sender();
    	let sender = sender.lock().unwrap();
    	sender.send(request).map_err(|_e| ProviderError::BadChannelSend)?;
    	self.get_and_handle_response(request, &Self::match_bytecode)
    }

    /// Get block hash by number from threaded DB via channels.
    fn request_block_hash(&mut self, number: U256) -> Result<Option<H256>> {
    	let request = DatabaseRequest::BlockHash(number);
    	let sender = self.request_sender();
    	let sender = sender.lock().unwrap();
    	sender.send(request).map_err(|_e| ProviderError::BadChannelSend)?;
    	self.get_and_handle_response(request, &Self::match_block_hash)
    }

    /// Takes an arbitrary response and a storage request, checks if the response matches. If it doesn't, it handles the out-of-order response
    /// and looks for the next response
    fn match_storage(&mut self, resp: DatabaseResponse<MAX_PREFETCH>, request: DatabaseRequest<MAX_PREFETCH>) -> Result<Option<StorageValue>> {
		match resp {
    		DatabaseResponse::Storage(db_addr, (key, maybe_value)) => {
    			// check that this response is the one we were expecting
    			match request {
    				DatabaseRequest::Storage(addr, slot) => {
    					if addr == db_addr && key == slot {
    						// the request and response match, return it
    						Ok(maybe_value)
    					} else {
    						// it doesnt match
    						self.cache_response(DatabaseResponse::Storage(db_addr, (key, maybe_value)));
			    			self.get_and_handle_response(request, &Self::match_storage)
    					}
    				}
    				_ => unreachable!()
    			}
    		}
    		other => {
    			self.cache_response(other);
    			self.get_and_handle_response(request, &Self::match_storage)
    		}
    	}
	}

	/// Takes an arbitrary response and a bytecode by hash request, checks if the response matches. If it doesn't, it handles the out-of-order response
    /// and looks for the next response
    fn match_bytecode(&mut self, resp: DatabaseResponse<MAX_PREFETCH>, request: DatabaseRequest<MAX_PREFETCH>) -> Result<Option<Bytes>> {
		match resp {
			DatabaseResponse::BytecodeFromHash(db_hash, maybe_bytecode) => {
				// check that this response is the one we were expecting
				match request {
    				DatabaseRequest::BytecodeFromHash(hash) => {
    					if hash == db_hash {
    						// the request and response match, return it
    						Ok(maybe_bytecode)
    					} else {
    						// it doesnt match
    						self.cache_response(DatabaseResponse::BytecodeFromHash(db_hash, maybe_bytecode));
			    			self.get_and_handle_response(request, &Self::match_bytecode)
    					}
    				}
    				_ => unreachable!()
    			}
    		}
    		other => {
    			self.cache_response(other);
    			self.get_and_handle_response(request, &Self::match_bytecode)
    		}
    	}
	}

	/// Takes an arbitrary response and a blockhash request, checks if the response matches. If it doesn't, it handles the out-of-order response
    /// and looks for the next response
    fn match_block_hash(&mut self, resp: DatabaseResponse<MAX_PREFETCH>, request: DatabaseRequest<MAX_PREFETCH>) -> Result<Option<H256>> {
    	match resp {
    		DatabaseResponse::BlockHash(num, maybe_hash) => {
    			match request {
    				DatabaseRequest::BlockHash(req_num) => {
    					// the response matches the request
    					if num == req_num {
    						Ok(maybe_hash)
    					} else {
    						// it doesnt match
    						self.cache_response(DatabaseResponse::BlockHash(num, maybe_hash));
			    			self.get_and_handle_response(request, &Self::match_block_hash)
    					}
    				}
    				_ => unreachable!()
    			}
    		}
    		other => {
    			self.cache_response(other);
    			self.get_and_handle_response(request, &Self::match_block_hash)
    		}
    	}
    }
}

/// Account provider
pub trait ThreadedChannelAccountProvider: ThreadedChannelAccountRequestor + CacheAccountProvider + Send + Sync {
    /// Get basic account information.
    ///
    /// Prioritizes using cached data first, then checks channel, finally requests from db if needed 
    fn basic_account(&mut self, address: Address) -> Result<Option<Account>> {
    	if let Some(cached) = CacheAccountProvider::basic_account(self, address) {
    		Ok(Some(cached))
    	} else {
    		// empty out buffer and add to cache. ideally we wouldn't allocate here but lifetimes are annoying
    		{
	    		let receiver = self.response_receiver();
	    		let receiver = receiver.lock().unwrap();
	    		receiver
	    			.try_iter()
	    			.collect::<Vec<DatabaseResponse<MAX_PREFETCH>>>()
	    			.into_iter()
	    			.for_each(|resp| self.cache_response(resp));
    		}
    		// recheck cache (ideally we stop early in handle_response)
    		if let Some(cached) = CacheAccountProvider::basic_account(self, address) {
	    		Ok(Some(cached))
	    	} else {
	    		self.request_basic_account(address)
	    	}
    	}
    }
}

/// Function needed for executor.
pub trait ThreadedChannelStateProvider: ThreadedChannelStateRequestor + CacheStateProvider + Send + Sync {
    /// Get storage.
    fn storage(&mut self, account: Address, storage_key: StorageKey) -> Result<Option<StorageValue>> {
    	if let Some(cached) = CacheStateProvider::storage(self, account, storage_key) {
    		Ok(Some(cached))
    	} else {
    		// empty out buffer and add to cache. ideally we wouldn't allocate here but lifetimes are annoying
    		{
	    		let receiver = self.response_receiver();
	    		let receiver = receiver.lock().unwrap();
	    		receiver
	    			.try_iter()
	    			.collect::<Vec<DatabaseResponse<MAX_PREFETCH>>>()
	    			.into_iter()
	    			.for_each(|resp| self.cache_response(resp));
    		}
    		// recheck cache (ideally we stop early in handle_response)
    		if let Some(cached) = CacheStateProvider::storage(self, account, storage_key) {
	    		Ok(Some(cached))
	    	} else {
	    		self.request_storage(account, storage_key)
	    	}
    	}
    }

    /// Get account code by its hash
    fn bytecode_by_hash(&mut self, code_hash: H256) -> Result<Option<Bytes>> {
    	if let Some(cached) = CacheStateProvider::bytecode_by_hash(self, code_hash) {
    		Ok(Some(cached))
    	} else {
    		// empty out buffer and add to cache. ideally we wouldn't allocate here but lifetimes are annoying
    		{
	    		let receiver = self.response_receiver();
	    		let receiver = receiver.lock().unwrap();
	    		receiver
	    			.try_iter()
	    			.collect::<Vec<DatabaseResponse<MAX_PREFETCH>>>()
	    			.into_iter()
	    			.for_each(|resp| self.cache_response(resp));
    		}
    		// recheck cache (ideally we stop early in handle_response)
    		if let Some(cached) = CacheStateProvider::bytecode_by_hash(self, code_hash) {
	    		Ok(Some(cached))
	    	} else {
	    		self.request_bytecode_by_hash(code_hash)
	    	}
    	}
    }

    /// Get block hash by number.
    fn block_hash(&mut self, number: U256) -> Result<Option<H256>> {
    	if let Some(cached) = CacheStateProvider::block_hash(self, number) {
    		Ok(Some(cached))
    	} else {
    		// empty out buffer and add to cache. ideally we wouldn't allocate here but lifetimes are annoying
    		{
	    		let receiver = self.response_receiver();
	    		let receiver = receiver.lock().unwrap();
	    		receiver
	    			.try_iter()
	    			.collect::<Vec<DatabaseResponse<MAX_PREFETCH>>>()
	    			.into_iter()
	    			.for_each(|resp| self.cache_response(resp));
    		}
    		// recheck cache (ideally we stop early in handle_response)
    		if let Some(cached) = CacheStateProvider::block_hash(self, number) {
	    		Ok(Some(cached))
	    	} else {
	    		self.request_block_hash(number)
	    	}
    	}
    }
}

