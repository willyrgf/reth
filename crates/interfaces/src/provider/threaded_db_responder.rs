#![allow(dead_code, unreachable_pub, unused_imports, missing_docs)]
use std::sync::{
    mpsc::{Receiver, Sender},
    Arc, Mutex,
};

use crate::{
    provider::{
        threaded_db_requestor::*, AccountProvider, Error as ProviderError, HeaderProvider,
        StateProvider, StateProviderFactory,
    },
    Result,
};
use reth_primitives::{Account, Address, Bytes, StorageKey, StorageValue, H256, U256};

/// A trait for a threaded db that communicates via channels
pub trait ThreadedChannelDB: StateProviderFactory {
    /// Run the request processor loop
    fn run(&mut self) -> Result<()> {
        // loop indefinitely as a listener to requests
        // if we get a "BadChannelSend", that means the otherside hung up and we should exit.
        //
        // TODO(brockelmore): support historical queries for specific heights in db requests
        loop {
            if let Ok(request) = self.request_receiver().lock().unwrap().try_recv() {
                let response_sender = self.response_sender();
                let response_sender = response_sender.lock().unwrap();
                match request {
                    DatabaseRequest::Basic(addr) => {
                        let basic = self.latest()?.basic_account(addr);
                        match basic {
                            Ok(maybe_db_acct_info) => response_sender
                                .send(DatabaseResponse::Basic(addr, maybe_db_acct_info))
                                .map_err(|_| ProviderError::BadChannelSend)?,
                            Err(_e) => {
                                // TODO(brockelmore): send the error in a DatabaseResponse::Error
                                // wrapper
                            }
                        }
                    }
                    DatabaseRequest::Storage(addr, slot) => {
                        let stor = self.latest()?.storage(addr, slot);
                        match stor {
                            Ok(maybe_value) => response_sender
                                .send(DatabaseResponse::Storage(addr, (slot, maybe_value)))
                                .map_err(|_| ProviderError::BadChannelSend)?,
                            Err(_e) => {
                                // TODO(brockelmore): send the error in a DatabaseResponse::Error
                                // wrapper
                            }
                        }
                    }
                    DatabaseRequest::BlockHash(number) => {
                        let hash = self.latest()?.block_hash(number);
                        match hash {
                            Ok(maybe_hash) => response_sender
                                .send(DatabaseResponse::BlockHash(number, maybe_hash))
                                .map_err(|_| ProviderError::BadChannelSend)?,
                            Err(_e) => {
                                // TODO(brockelmore): send the error in a DatabaseResponse::Error
                                // wrapper
                            }
                        }
                    }
                    DatabaseRequest::BytecodeFromHash(code_hash) => {
                        let code = self.latest()?.bytecode_by_hash(code_hash);
                        match code {
                            Ok(maybe_code) => response_sender
                                .send(DatabaseResponse::BytecodeFromHash(code_hash, maybe_code))
                                .map_err(|_| ProviderError::BadChannelSend)?,
                            Err(_e) => {
                                // TODO(brockelmore): send the error in a DatabaseResponse::Error
                                // wrapper
                            }
                        }
                    }
                    DatabaseRequest::MultiStorage(_addr, _slots) => {
                        todo!()
                    }
                }
            }
        }
    }
    /// Gets the database request receiver
    fn request_receiver(&mut self) -> Arc<Mutex<Receiver<DatabaseRequest<MAX_PREFETCH>>>>;
    /// Gets the database response sender
    fn response_sender(&mut self) -> Arc<Mutex<Sender<DatabaseResponse<MAX_PREFETCH>>>>;
}
