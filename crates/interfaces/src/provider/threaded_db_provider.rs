#![allow(unreachable_pub, missing_docs)]
//! Provider that wraps around database traits.
//! to provide higher level abstraction over database tables.

use crate::{
    db::{tables, Database, DatabaseGAT, DbTx},
    provider::{
        db_provider::{StateProviderImplHistory, StateProviderImplLatest},
        threaded_db_requestor::{DatabaseRequest, DatabaseResponse, MAX_PREFETCH},
        threaded_db_responder::ThreadedChannelDB,
        Error, StateProviderFactory,
    },
    Result,
};
use reth_primitives::{BlockHash, BlockNumber};
use std::sync::{
    mpsc::{Receiver, Sender},
    Arc, Mutex,
};

/// Provider
pub struct BasicThreadedDB<DB: Database> {
    /// Database
    pub db: Arc<DB>,
    request_receiver: Arc<Mutex<Receiver<DatabaseRequest<MAX_PREFETCH>>>>,
    response_sender: Arc<Mutex<Sender<DatabaseResponse<MAX_PREFETCH>>>>,
}

impl<DB: Database> BasicThreadedDB<DB> {
    /// create new database provider
    pub fn new(
        db: Arc<DB>,
        request_receiver: Arc<Mutex<Receiver<DatabaseRequest<MAX_PREFETCH>>>>,
        response_sender: Arc<Mutex<Sender<DatabaseResponse<MAX_PREFETCH>>>>,
    ) -> Self {
        Self { db, request_receiver, response_sender }
    }
}

impl<DB: Database> ThreadedChannelDB for BasicThreadedDB<DB> {
    fn request_receiver(&mut self) -> Arc<Mutex<Receiver<DatabaseRequest<MAX_PREFETCH>>>> {
        self.request_receiver.clone()
    }

    fn response_sender(&mut self) -> Arc<Mutex<Sender<DatabaseResponse<MAX_PREFETCH>>>> {
        self.response_sender.clone()
    }
}

impl<DB: Database> StateProviderFactory for BasicThreadedDB<DB> {
    type HistorySP<'a> = StateProviderImplHistory<'a,<DB as DatabaseGAT<'a>>::TX> where Self: 'a;
    type LatestSP<'a> = StateProviderImplLatest<'a,<DB as DatabaseGAT<'a>>::TX> where Self: 'a;
    /// Storage provider for latest block
    fn latest(&self) -> Result<Self::LatestSP<'_>> {
        Ok(StateProviderImplLatest::new(self.db.tx()?))
    }

    fn history_by_block_number(&self, block_number: BlockNumber) -> Result<Self::HistorySP<'_>> {
        let tx = self.db.tx()?;
        // get block hash
        let block_hash = tx
            .get::<tables::CanonicalHeaders>(block_number)?
            .ok_or(Error::BlockNumberNotExists { block_number })?;

        // get transaction number
        let block_num_hash = (block_number, block_hash);
        let transaction_number = tx
            .get::<tables::CumulativeTxCount>(block_num_hash.into())?
            .ok_or(Error::BlockTxNumberNotExists { block_hash })?;

        Ok(StateProviderImplHistory::new(tx, transaction_number))
    }

    fn history_by_block_hash(&self, block_hash: BlockHash) -> Result<Self::HistorySP<'_>> {
        let tx = self.db.tx()?;
        // get block number
        let block_number = tx
            .get::<tables::HeaderNumbers>(block_hash)?
            .ok_or(Error::BlockHashNotExist { block_hash })?;

        // get transaction number
        let block_num_hash = (block_number, block_hash);
        let transaction_number = tx
            .get::<tables::CumulativeTxCount>(block_num_hash.into())?
            .ok_or(Error::BlockTxNumberNotExists { block_hash })?;

        Ok(StateProviderImplHistory::new(tx, transaction_number))
    }
}