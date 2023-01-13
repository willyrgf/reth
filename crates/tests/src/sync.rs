use crate::{
    clique::{block_to_header, genesis_header, genesis_to_chainspec, CliqueGethBuilder},
    reth_builder::{RethBuilder, RethTestInstance},
};
use enr::k256::ecdsa::SigningKey;
use ethers_core::types::{
    transaction::eip2718::TypedTransaction, BlockNumber, Eip1559TransactionRequest, H160, U64,
};
use ethers_middleware::SignerMiddleware;
use ethers_providers::{Middleware, Provider, Ws};
use ethers_signers::{LocalWallet, Signer, Wallet};
use reth_cli_utils::init::init_db;
use reth_consensus::BeaconConsensus;
use reth_db::mdbx::{Env, WriteMap};
use reth_net_test_utils::{enr_to_peer_id, unused_tcp_udp, NetworkEventStream, GETH_TIMEOUT};
use reth_network::{NetworkConfig, NetworkManager};
use reth_primitives::{PeerId, H256};
use reth_provider::test_utils::NoopProvider;
use secp256k1::SecretKey;
use std::{
    io::{BufRead, BufReader},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{fs, task};

/// Creates an ethers provider, passing the provided private key to `personal_importRawKey`,
/// unlocking it, and starting block production by starting mining.
async fn produce_blocks(
    rpc_port: u16,
    private_key: SigningKey,
) -> SignerMiddleware<Provider<Ws>, Wallet<SigningKey>> {
    // create the signer
    let wallet: LocalWallet = private_key.clone().into();
    let our_address = wallet.address();

    // set up ethers provider
    let geth_endpoint = SocketAddr::new([127, 0, 0, 1].into(), rpc_port).to_string();
    let provider = Provider::<Ws>::connect(format!("ws://{geth_endpoint}")).await.unwrap();
    let provider =
        SignerMiddleware::new_with_provider_chain(provider, wallet.clone()).await.unwrap();

    // first get the balance and make sure its not zero
    let balance = provider.get_balance(our_address, None).await.unwrap();
    assert_ne!(balance, 0u64.into());
    println!("address: {our_address:?}");
    println!("balance at genesis: {balance:?}");

    // send the private key to geth and unlock it
    let key_bytes = private_key.to_bytes().to_vec().into();
    println!("private key: {}", hex::encode(&key_bytes));
    let unlocked_addr = provider.import_raw_key(key_bytes, "".to_string()).await.unwrap();
    assert_eq!(unlocked_addr, our_address);

    let unlock_success = provider.unlock_account(our_address, "".to_string(), None).await.unwrap();
    assert!(unlock_success);

    // start mining?
    provider.start_mining(None).await.unwrap();

    // check that we are mining
    let mining = provider.mining().await.unwrap();
    assert!(mining);

    provider
}

/// Integration tests for the full sync pipeline.
///
/// Tests that are run against a real `geth` node use geth's Clique functionality to create blocks.
#[tokio::test(flavor = "multi_thread")]
async fn sync_from_clique_geth() {
    reth_tracing::init_test_tracing();
    tokio::time::timeout(GETH_TIMEOUT, async move {
        // first create a signer that we will fund so we can make transactions
        let chain_id = 13337u64;
        let data_dir = tempfile::tempdir().expect("should be able to create temp geth datadir");
        let dir_path = data_dir.into_path();

        // this creates a funded geth
        let clique_geth = CliqueGethBuilder::new()
            .chain_id(chain_id)
            .data_dir(dir_path.to_str().unwrap().into());

        // build the funded geth
        let (geth, status, genesis, signing_key) = clique_geth.build();

        // geth starts in dev mode, we can spawn it, mine blocks, and shut it down we need to clone
        // it because we will be reusing the geth config when we restart p2p
        let mut instance = geth.spawn();

        // take the stderr of the geth instance and print it
        let stderr = instance.stderr().unwrap();

        // print logs in a new task
        task::spawn(async move {
            let mut err_reader = BufReader::new(stderr);

            loop {

                let mut buf = String::new();
                if let Ok(line) = err_reader.read_line(&mut buf) {
                    if line == 0 {
                        tokio::time::sleep(Duration::from_nanos(1)).await;
                        continue
                    }
                    dbg!(buf);
                }
            }
        });

        // === check that we have the same genesis hash ===

        // set up provider
        let provider = produce_blocks(instance.port(), signing_key).await;

        // get genesis hash
        let genesis_block =
            provider.get_block(0).await.unwrap().expect("a genesis block should exist");

        // get our hash
        let sealed_genesis = genesis_header(&genesis.clone()).seal();

        // let's just convert into a reth header and compare
        let geth_genesis_header = block_to_header(genesis_block.clone()).seal();
        assert_eq!(geth_genesis_header, sealed_genesis, "genesis headers should match, we computed {sealed_genesis:#?} but geth computed {geth_genesis_header:#?}");

        // make sure we have the same genesis hash
        let genesis_hash: H256 = genesis_block.hash.unwrap().0.into();
        let sealed_hash = sealed_genesis.hash();
        assert_eq!(sealed_hash, genesis_hash, "genesis hashes should match, we computed {sealed_hash:?} but geth computed {genesis_hash:?}");

        // === create many blocks ===

        let nonces = 0..10000u64;
        let txs = nonces
            .map(|nonce| {
                // create a tx that just sends to the zero addr
                TypedTransaction::Eip1559(Eip1559TransactionRequest::new()
                    .to(H160::zero())
                    .value(1u64)
                    .nonce(nonce))
            });

        for tx in txs {
            // send the tx - geth will mine a block with just this transaction in it if we await
            // here rather than joining concurrent sends
            provider.send_transaction(tx, None).await.unwrap();
        }

        // wait for a certain number of blocks to be mined
        let block = provider.get_block_number().await.unwrap();
        println!("block num after creating transactions: {block}");
        assert!(block > U64::zero());

        // get the tip so we can send it to reth
        let tip_block = provider.get_block(BlockNumber::Latest).await.unwrap().unwrap();
        let tip_hash = tip_block.hash.unwrap().0.into();

        // === initialize reth networking stack ===

        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let (reth_p2p, reth_disc) = unused_tcp_udp();

        // may not need to set up a hello as we should be advertising compatible capabilities and
        // protocol versions anyways
        // TODO: it's sort of redundant setting BOTH the status and the genesis hash, since they
        // both contain the genesis hash. a discrepancy is probably an error. could we enforce this
        // somethow?
        let config = NetworkConfig::builder(Arc::new(NoopProvider::default()), secret_key)
            .listener_addr(reth_p2p)
            .discovery_addr(reth_disc)
            .genesis_hash(sealed_genesis.hash())
            .status(status)
            .build();

        let network = NetworkManager::new(config).await.unwrap();
        let handle = network.handle().clone();

        // convert ethers genesis to chainspec
        let chainspec = genesis_to_chainspec(&genesis);

        // initialize db
        let reth_temp_dir = tempfile::tempdir().expect("should be able to create reth data dir");
        let db = Arc::new(init_db(reth_temp_dir.path()).unwrap());

        // initialize consensus
        let consensus = Arc::new(BeaconConsensus::new(chainspec.consensus));

        // build reth and start the pipeline
        let reth: RethTestInstance<Env<WriteMap>> = RethBuilder::new()
            .db(db)
            .consensus(consensus)
            .genesis(chainspec.genesis)
            .network(handle.clone())
            .tip(tip_hash)
            .build();

        // start reth then manually connect geth
        let pipeline_handle = tokio::task::spawn(async move { reth.start().await });
        tokio::task::spawn(network);

        // create networkeventstream to get the next session established event easily
        let mut events = NetworkEventStream::new(handle.event_listener());
        let geth_p2p_port = instance.p2p_port().unwrap();
        let geth_socket = SocketAddr::new([127, 0, 0, 1].into(), geth_p2p_port);

        // === ensure p2p is active ===

        // get the peer id we should be expecting
        let geth_peer_id: PeerId = enr_to_peer_id(provider.node_info().await.unwrap().enr);

        // add geth as a peer then wait for `PeerAdded` and `SessionEstablished` events.
        handle.add_peer(geth_peer_id, geth_socket);

        // wait for the session to be established
        let _peer_id = events.peer_added_and_established().await.unwrap();

        pipeline_handle.await.unwrap().unwrap();

        // cleanup (delete the data_dir at dir_path)
        fs::remove_dir_all(dir_path).await.unwrap();
    })
    .await
    .unwrap();
}
