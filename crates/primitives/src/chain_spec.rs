use hex_literal::hex;
use once_cell::sync::Lazy;
use std::collections::BTreeMap;
use ethers_core::utils::Genesis as EthersGenesis;
use serde::{Deserialize, Serialize};
use crate::{BlockNumber, Chain, ForkFilter, ForkHash, ForkId, Genesis, Hardfork, H256, U256};

/// The Etereum mainnet spec
pub static MAINNET: Lazy<ChainSpec> = Lazy::new(|| ChainSpec {
    chain: Chain::mainnet(),
    genesis: serde_json::from_str(include_str!("../res/genesis/mainnet.json"))
        .expect("Can't deserialize Mainnet genesis json"),
    genesis_hash: H256(hex!("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")),
    hardforks: BTreeMap::from([
        (Hardfork::Frontier, 0),
        (Hardfork::Homestead, 1150000),
        (Hardfork::Dao, 1920000),
        (Hardfork::Tangerine, 2463000),
        (Hardfork::SpuriousDragon, 2675000),
        (Hardfork::Byzantium, 4370000),
        (Hardfork::Constantinople, 7280000),
        (Hardfork::Petersburg, 7280000),
        (Hardfork::Istanbul, 9069000),
        (Hardfork::Muirglacier, 9200000),
        (Hardfork::Berlin, 12244000),
        (Hardfork::London, 12965000),
        (Hardfork::ArrowGlacier, 13773000),
        (Hardfork::GrayGlacier, 15050000),
        (Hardfork::Latest, 15050000),
    ]),
    dao_fork_support: true,
    paris_block: Some(15537394),
    paris_ttd: Some(U256::from(58750000000000000000000_u128)),
});

/// The Goerli spec
pub static GOERLI: Lazy<ChainSpec> = Lazy::new(|| ChainSpec {
    chain: Chain::goerli(),
    genesis: serde_json::from_str(include_str!("../res/genesis/goerli.json"))
        .expect("Can't deserialize Goerli genesis json"),
    genesis_hash: H256(hex!("bf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a")),
    hardforks: BTreeMap::from([
        (Hardfork::Frontier, 0),
        (Hardfork::Istanbul, 1561651),
        (Hardfork::Berlin, 4460644),
        (Hardfork::London, 5062605),
    ]),
    dao_fork_support: true,
    paris_block: Some(7382818),
    paris_ttd: Some(U256::from(10790000)),
});

/// The Sepolia spec
pub static SEPOLIA: Lazy<ChainSpec> = Lazy::new(|| ChainSpec {
    chain: Chain::sepolia(),
    genesis: serde_json::from_str(include_str!("../res/genesis/sepolia.json"))
        .expect("Can't deserialize Sepolia genesis json"),
    genesis_hash: H256(hex!("25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9")),
    hardforks: BTreeMap::new(),
    dao_fork_support: true,
    paris_block: Some(1450408),
    paris_ttd: Some(U256::from(17000000000000000_u64)),
});

/// The Ethereum chain spec
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainSpec {
    chain: Chain,
    genesis: Genesis,
    genesis_hash: H256,
    hardforks: BTreeMap<Hardfork, BlockNumber>,
    dao_fork_support: bool,
    paris_block: Option<u64>,
    paris_ttd: Option<U256>,
}

impl ChainSpec {
    /// Returns the chain id
    pub fn chain(&self) -> Chain {
        self.chain
    }

    /// Returns the chain genesis hash
    pub fn genesis_hash(&self) -> H256 {
        self.genesis_hash
    }

    /// Get the first block number of the hardfork.
    pub fn fork_block(&self, fork: Hardfork) -> Option<BlockNumber> {
        self.hardforks.get(&fork).copied()
    }

    /// Returns `true` if the given fork is active on the given block
    pub fn fork_active(&self, fork: Hardfork, current_block: BlockNumber) -> bool {
        self.fork_block(fork).map(|target| target <= current_block).unwrap_or_default()
    }

    /// Returns `true` if the DAO fork is supported
    pub fn dao_fork_support(&self) -> bool {
        self.dao_fork_support
    }

    /// Get the Paris status
    pub fn paris_status(&self) -> ParisStatus {
        match self.paris_ttd {
            Some(terminal_total_difficulty) => {
                ParisStatus::Supported { terminal_total_difficulty, block: self.paris_block }
            }
            None => ParisStatus::NotSupported,
        }
    }

    /// Get an iterator of all harforks with theirs respectives block number
    pub fn forks_iter(&self) -> impl Iterator<Item = (Hardfork, BlockNumber)> + '_ {
        self.hardforks.iter().map(|(f, b)| (*f, *b))
    }

    /// Creates a [`ForkFilter`](crate::ForkFilter) for the given [BlockNumber].
    pub fn fork_filter(&self, block: BlockNumber) -> ForkFilter {
        let future_forks =
            self.forks_iter().map(|(_, b)| b).filter(|b| *b > block).collect::<Vec<_>>();

        ForkFilter::new(block, self.genesis_hash(), future_forks)
    }

    /// Compute the forkid for the given [BlockNumber]
    pub fn fork_id(&self, block: BlockNumber) -> ForkId {
        let mut curr_forkhash = ForkHash::from(self.genesis_hash());
        let mut curr_block_number = 0;

        for (_, b) in self.forks_iter() {
            if block >= b {
                if b != curr_block_number {
                    curr_forkhash += b;
                    curr_block_number = b;
                }
            } else {
                return ForkId { hash: curr_forkhash, next: b }
            }
        }
        ForkId { hash: curr_forkhash, next: 0 }
    }

    /// Returns a [ChainSpecBuilder] to help build custom specs
    pub fn builder() -> ChainSpecBuilder {
        ChainSpecBuilder::default()
    }

    // TODO: check if our fork calculation based on chainspec is correct
    ///// Obtains the list of the config's fork block numbers in order of activation.
    ///// This only lists forks that were activated by block number, with a notable exception being
    ///// the merge, also known as Paris.
    /////
    ///// This should be the same as [Geth's `gather_forks`
    ///// method](https://github.com/ethereum/go-ethereum/blob/6c149fd4ad063f7c24d726a73bc0546badd1bc73/core/forkid/forkid.go#L215).
    // pub fn fork_blocks(&self) -> Vec<BlockNumber> {
    //     // will just put each consecutive fork in a vec
    //     let mut fork_blocks_opt: Vec<Option<u64>> = vec![
    //         self.homestead_block.into(),
    //         self.dao_fork_block.into(),
    //         self.eip_150_block.into(),
    //         self.eip_155_block.into(),
    //         self.eip_158_block.into(),
    //         self.byzantium_block.into(),
    //         self.constantinople_block.into(),
    //         self.petersburg_block.into(),
    //         self.istanbul_block.into(),
    //         self.muir_glacier_block.into(),
    //         self.berlin_block.into(),
    //         self.london_block.into(),
    //         self.arrow_glacier_block.into(),
    //         self.gray_glacier_block.into(),
    //         self.merge_netsplit_block,
    //         // TODO: when cancun time is known
    //         // self.cancun_time,
    //         // TODO: when shangai time is known
    //         // self.shanghai_time,
    //     ];

    //     // filter out the None values
    //     fork_blocks_opt.retain(|block| block.is_some());

    //     // SAFETY: it ok to use unwrap because the vec is now guaranteed to have no None values
    //     let mut fork_blocks: Vec<u64> =
    //         fork_blocks_opt.iter().map(|block| block.unwrap()).collect();

    //     // Sort the fork block numbers to permit chronological XOR
    //     fork_blocks.sort();

    //     // Deduplicate block numbers applying multiple forks (each block number should only be
    //     // represented once)
    //     fork_blocks_opt.dedup();

    //     // Skip any forks in block 0, that's the genesis ruleset
    //     fork_blocks.retain(|block| *block != 0);
    //     fork_blocks
    // }
}

impl From<EthersGenesis> for ChainSpec {
    fn from(_genesis: EthersGenesis) -> Self {
        // let alloc = genesis
        //     .alloc
        //     .iter()
        //     .map(|(addr, account)| (addr.0.into(), account.clone().into()))
        //     .collect::<HashMap<H160, GenesisAccount>>();

        todo!()
        // Self {
        //     chain: genesis.config.chain_id.into()
        //     consensus: reth_consensus::Config {
        //         chain_id: genesis.config.chain_id,
        //         homestead_block: genesis.config.homestead_block.unwrap_or_default(),
        //         dao_fork_block: genesis.config.dao_fork_block.unwrap_or_default(),
        //         dao_fork_support: genesis.config.dao_fork_support,
        //         eip_150_block: genesis.config.eip150_block.unwrap_or_default(),
        //         eip_155_block: genesis.config.eip155_block.unwrap_or_default(),
        //         eip_158_block: genesis.config.eip158_block.unwrap_or_default(),
        //         byzantium_block: genesis.config.byzantium_block.unwrap_or_default(),
        //         petersburg_block: genesis.config.petersburg_block.unwrap_or_default(),
        //         constantinople_block: genesis.config.constantinople_block.unwrap_or_default(),
        //         istanbul_block: genesis.config.istanbul_block.unwrap_or_default(),
        //         muir_glacier_block: genesis.config.muir_glacier_block.unwrap_or_default(),
        //         berlin_block: genesis.config.berlin_block.unwrap_or_default(),
        //         london_block: genesis.config.london_block.unwrap_or_default(),
        //         arrow_glacier_block: genesis.config.arrow_glacier_block.unwrap_or_default(),
        //         gray_glacier_block: genesis.config.gray_glacier_block.unwrap_or_default(),
        //         merge_netsplit_block: genesis.config.merge_netsplit_block,
        //         merge_terminal_total_difficulty: genesis
        //             .config
        //             .terminal_total_difficulty
        //             .unwrap_or_default()
        //             .as_u128(),
        //         ..Default::default() // TODO: when paris_block is removed, remove this
        //     },
        //     genesis: Genesis {
        //         nonce: genesis.nonce.as_u64(),
        //         timestamp: genesis.timestamp.as_u64(),
        //         gas_limit: genesis.gas_limit.as_u64(),
        //         difficulty: genesis.difficulty.into(),
        //         mix_hash: genesis.mix_hash.0.into(),
        //         coinbase: genesis.coinbase.0.into(),
        //         extra_data: genesis.extra_data.0.into(),
        //         alloc,
        //     },
        // }
    }
}


/// A helper to build custom chain specs
#[derive(Debug, Default)]
pub struct ChainSpecBuilder {
    chain: Option<Chain>,
    genesis: Option<Genesis>,
    genesis_hash: Option<H256>,
    hardforks: BTreeMap<Hardfork, BlockNumber>,
    dao_fork_support: bool,
    paris_block: Option<u64>,
    paris_ttd: Option<U256>,
}

impl ChainSpecBuilder {
    /// Returns a [ChainSpec] builder initialized with Ethereum mainnet config
    pub fn mainnet() -> Self {
        Self {
            chain: Some(MAINNET.chain),
            genesis: Some(MAINNET.genesis.clone()),
            genesis_hash: Some(MAINNET.genesis_hash),
            hardforks: MAINNET.hardforks.clone(),
            dao_fork_support: MAINNET.dao_fork_support,
            paris_block: MAINNET.paris_block,
            paris_ttd: MAINNET.paris_ttd,
        }
    }

    /// Sets the chain id
    pub fn chain(mut self, chain: Chain) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Sets the genesis
    pub fn genesis(mut self, genesis: Genesis) -> Self {
        self.genesis = Some(genesis);
        self
    }

    /// Insert the given fork at the given block number
    pub fn with_fork(mut self, fork: Hardfork, block: BlockNumber) -> Self {
        self.hardforks.insert(fork, block);
        self
    }

    /// Enables Frontier
    pub fn frontier_activated(mut self) -> Self {
        self.hardforks.insert(Hardfork::Frontier, 0);
        self
    }

    /// Enables Homestead
    pub fn homestead_activated(mut self) -> Self {
        self = self.frontier_activated();
        self.hardforks.insert(Hardfork::Homestead, 0);
        self
    }

    /// Enables Tangerine
    pub fn tangerine_whistle_activated(mut self) -> Self {
        self = self.homestead_activated();
        self.hardforks.insert(Hardfork::Tangerine, 0);
        self
    }

    /// Enables SpuriousDragon
    pub fn spurious_dragon_activated(mut self) -> Self {
        self = self.tangerine_whistle_activated();
        self.hardforks.insert(Hardfork::SpuriousDragon, 0);
        self
    }

    /// Enables Byzantium
    pub fn byzantium_activated(mut self) -> Self {
        self = self.spurious_dragon_activated();
        self.hardforks.insert(Hardfork::Byzantium, 0);
        self
    }

    /// Enables Petersburg
    pub fn petersburg_activated(mut self) -> Self {
        self = self.byzantium_activated();
        self.hardforks.insert(Hardfork::Petersburg, 0);
        self
    }

    /// Enables Istanbul
    pub fn istanbul_activated(mut self) -> Self {
        self = self.petersburg_activated();
        self.hardforks.insert(Hardfork::Istanbul, 0);
        self
    }

    /// Enables Berlin
    pub fn berlin_activated(mut self) -> Self {
        self = self.istanbul_activated();
        self.hardforks.insert(Hardfork::Berlin, 0);
        self
    }

    /// Enables London
    pub fn london_activated(mut self) -> Self {
        self = self.berlin_activated();
        self.hardforks.insert(Hardfork::London, 0);
        self
    }

    /// Sets the DAO fork as supported
    pub fn dao_fork_supported(mut self) -> Self {
        self.dao_fork_support = true;
        self
    }

    /// Enables Paris
    pub fn paris_activated(mut self) -> Self {
        self = self.berlin_activated();
        self.paris_block = Some(0);
        self
    }

    /// Build a [ChainSpec]
    pub fn build(self) -> ChainSpec {
        ChainSpec {
            chain: self.chain.expect("The chain is required"),
            genesis: self.genesis.expect("The genesis is required"),
            genesis_hash: self.genesis_hash.expect("The genesis hash is required"),
            hardforks: self.hardforks,
            dao_fork_support: self.dao_fork_support,
            paris_block: self.paris_block,
            paris_ttd: self.paris_ttd,
        }
    }
}

impl From<&ChainSpec> for ChainSpecBuilder {
    fn from(value: &ChainSpec) -> Self {
        Self {
            chain: Some(value.chain),
            genesis: Some(value.genesis.clone()),
            genesis_hash: Some(value.genesis_hash),
            hardforks: value.hardforks.clone(),
            dao_fork_support: value.dao_fork_support,
            paris_block: value.paris_block,
            paris_ttd: value.paris_ttd,
        }
    }
}

/// Merge Status
#[derive(Debug)]
pub enum ParisStatus {
    /// Paris is not supported
    NotSupported,
    /// Paris settings has been set in the chain spec
    Supported {
        /// The merge terminal total difficulty
        terminal_total_difficulty: U256,
        /// The Paris block number
        block: Option<BlockNumber>,
    },
}

impl ParisStatus {
    /// Returns the Paris block number if it is known ahead of time.
    ///
    /// This is only the case for chains that have already activated the merge.
    pub fn block_number(&self) -> Option<BlockNumber> {
        match &self {
            ParisStatus::NotSupported => None,
            ParisStatus::Supported { block, .. } => *block,
        }
    }

    /// Returns the merge terminal total difficulty
    pub fn terminal_total_difficulty(&self) -> Option<U256> {
        match &self {
            ParisStatus::NotSupported => None,
            ParisStatus::Supported { terminal_total_difficulty, .. } => {
                Some(*terminal_total_difficulty)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::MAINNET;

    #[test]
    // this test checks that the forkid computation is accurate
    fn test_forkid_from_hardfork() {
        let frontier_forkid = MAINNET.fork_id(0);
        assert_eq!([0xfc, 0x64, 0xec, 0x04], frontier_forkid.hash.0);
        assert_eq!(1150000, frontier_forkid.next);

        let berlin_forkid = MAINNET.fork_id(12244000);
        assert_eq!([0x0e, 0xb4, 0x40, 0xf6], berlin_forkid.hash.0);
        assert_eq!(12965000, berlin_forkid.next);

        let latest_forkid = MAINNET.fork_id(15050000);
        assert_eq!(0, latest_forkid.next);
    }
}
