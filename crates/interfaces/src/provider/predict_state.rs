// use crate::provider::StateProvider;
// use crate::provider::ProviderImpl;
// use crate::provider::StateProviderFactory;

// use std::num::NonZeroUsize;
// use std::sync::Arc;
// use crate::db::Database;

// use reth_primitives::{
//     Address, StorageValue, U256, H256,
// };
// use std::sync::mpsc::{Receiver, Sender};
// use lru::LruCache;

// /// Data used for sload prefetching
// pub struct PrefetchData {
// 	pub access_list: AccessList,
// 	pub selector: [u8; 4],
// }

// pub trait DatabasePipeline<const ChannelSize: usize> {
// 	fn basic_request(&mut self, )
// 	fn storage_request(&mut self, account: Address, slot: H256) -> U256;
// 	fn prefetch_storage_request(&mut self, account: Address, data: PrefetchData);
// }

// /// Function needed for executor.
// pub(crate) trait PredictionStateProvider {
//     /// Get prediction storage
//     fn predict_storage_reads<P: StateProvider>(lru: &mut StateLru, provider: P, sender:
// Sender<StorageValue>, account: Address, selector: [u8; 4]);

//     /// Update prediction for selector
//     fn update_predictions(&mut self, selector: [u8; 4], account: Address, num_reads: u8, reads:
// [U256; 4]); }

// pub enum StorageRequest {
// 	PredictionWarm(Address, [u8; 4]),
// 	Sload(Address, H256),
// }

// type StateLru = LruCache<(Address, [u8; 4]), (u8, [H256; 4])>;

// /// Predictor
// pub struct Predictor<P: StateProviderFactory> {
//     /// Database
//     pub provider: P,
//     /// Sends SLOADed values
//     pub sload_sender: Sender<StorageValue>,
//     /// Receives SLOAD requests (either prediction or normal)
//     pub request_receiver: Receiver<StorageRequest>,
//     /// selector reader, the cache value is an ordered list of slots to load on request
// 	pub lru_addr_selector_reads: StateLru,
// }

// impl<DB: Database> Predictor<ProviderImpl<DB>> {
// 	/// Creates a new Predictor storage provider
// 	pub fn new(db: Arc<DB>, sload_sender: Sender<StorageValue>, request_receiver:
// Receiver<StorageRequest>, lru_cap: usize) -> Self { 		Self {
// 			provider: ProviderImpl::new(db),
// 			sload_sender,
// 			request_receiver,
// 			lru_addr_selector_reads: LruCache::new(NonZeroUsize::new(lru_cap).unwrap())
// 		}
// 	}

// 	/// Starts the receiver loop
// 	pub fn start(&mut self) {
// 		let lru = &mut self.lru_addr_selector_reads;

// 		let rx = &self.request_receiver;
// 		for rec in rx {

// 			match rec {
// 				StorageRequest::PredictionWarm(addr, selector) => {
// 					let provider = self.provider.latest().expect("REASON");
// 					let sender = self.sload_sender.clone();
// 					Self::predict_storage_reads(lru, provider, sender, addr, selector)
// 				}
// 				StorageRequest::Sload(addr, slot) => {
// 					let val = self.provider.latest().expect("REASON").storage(addr,
// slot).expect("REASON").unwrap_or(U256::zero()); 					self.sload_sender.send(val).expect("BAD SEND");
// 				}
// 			}
// 		}
// 	}
// }

// impl<P: StateProviderFactory> PredictionStateProvider for Predictor<P> {
//     fn predict_storage_reads<P2: StateProvider>(lru: &mut StateLru, provider: P2, sender:
// Sender<StorageValue>, account: Address, selector: [u8; 4]) {     	if let Some((num, reads)) =
// lru.get(&(account, selector)) {     		for i in 0..*num {
//     			let val = provider.storage(account, reads[i as
// usize]).expect("REASON").unwrap_or(U256::zero()); 	    		sender.send(val).expect("BAD SEND");
// 	    	}
//     	} else {
//     		// we dont know what to use,
//     	}
//     }
// 	fn update_predictions(&mut self, _: [u8; 4], _: reth_primitives::H160, _: u8, _:
// [reth_primitives::U256; 4]) { todo!() } }
