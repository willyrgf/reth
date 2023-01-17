use ethers_core::utils::Genesis as EthersGenesis;
use reth_primitives::{
    proofs::genesis_state_root, utils::serde_helpers::deserialize_stringified_u64, Address, Bytes,
    ForkHash, GenesisAccount, Header, H160, H256, INITIAL_BASE_FEE, U256,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

/// Defines a chain, including it's genesis block, chain ID and fork block numbers.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChainSpecification {
    /// Consensus configuration.
    #[serde(rename = "config")]
    pub consensus: reth_consensus::Config,
    /// The genesis block of the chain.
    #[serde(flatten)]
    pub genesis: Genesis,
}

impl ChainSpecification {
    /// Obtains a [`ForkHash`] based on the genesis hash and configured forks activated by block
    /// number.
    pub fn fork_hash(&self) -> ForkHash {
        let mut genesis_header = Header::from(self.genesis.clone());

        // set initial base fee depending on eip-1559
        if self.consensus.london_block == 0 {
            genesis_header.base_fee_per_gas = Some(INITIAL_BASE_FEE);
        }

        let fork_blocks = self.consensus.fork_blocks();
        let sealed_genesis = genesis_header.seal();
        fork_blocks.iter().fold(ForkHash::from(sealed_genesis.hash()), |acc, block| acc + *block)
    }
}

/// The genesis block specification.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Genesis {
    /// The genesis header nonce.
    #[serde(deserialize_with = "deserialize_stringified_u64")]
    pub nonce: u64,
    /// The genesis header timestamp.
    #[serde(deserialize_with = "deserialize_stringified_u64")]
    pub timestamp: u64,
    /// The genesis header extra data.
    pub extra_data: Bytes,
    /// The genesis header gas limit.
    #[serde(deserialize_with = "deserialize_stringified_u64")]
    pub gas_limit: u64,
    /// The genesis header difficulty.
    pub difficulty: U256,
    /// The genesis header mix hash.
    pub mix_hash: H256,
    /// The genesis header coinbase address.
    pub coinbase: Address,
    /// The initial state of accounts in the genesis block.
    pub alloc: HashMap<Address, GenesisAccount>,
}

impl From<Genesis> for Header {
    fn from(genesis: Genesis) -> Header {
        Header {
            gas_limit: genesis.gas_limit,
            difficulty: genesis.difficulty,
            nonce: genesis.nonce,
            extra_data: genesis.extra_data,
            state_root: genesis_state_root(genesis.alloc),
            timestamp: genesis.timestamp,
            mix_hash: genesis.mix_hash,
            beneficiary: genesis.coinbase,
            ..Default::default()
        }
    }
}

impl From<EthersGenesis> for ChainSpecification {
    fn from(genesis: EthersGenesis) -> Self {
        let alloc = genesis
            .alloc
            .iter()
            .map(|(addr, account)| (addr.0.into(), account.clone().into()))
            .collect::<HashMap<H160, GenesisAccount>>();

        Self {
            consensus: reth_consensus::Config {
                chain_id: genesis.config.chain_id,
                homestead_block: genesis.config.homestead_block.unwrap_or_default(),
                dao_fork_block: genesis.config.dao_fork_block.unwrap_or_default(),
                dao_fork_support: genesis.config.dao_fork_support,
                eip_150_block: genesis.config.eip150_block.unwrap_or_default(),
                eip_155_block: genesis.config.eip155_block.unwrap_or_default(),
                eip_158_block: genesis.config.eip158_block.unwrap_or_default(),
                byzantium_block: genesis.config.byzantium_block.unwrap_or_default(),
                petersburg_block: genesis.config.petersburg_block.unwrap_or_default(),
                constantinople_block: genesis.config.constantinople_block.unwrap_or_default(),
                istanbul_block: genesis.config.istanbul_block.unwrap_or_default(),
                muir_glacier_block: genesis.config.muir_glacier_block.unwrap_or_default(),
                berlin_block: genesis.config.berlin_block.unwrap_or_default(),
                london_block: genesis.config.london_block.unwrap_or_default(),
                arrow_glacier_block: genesis.config.arrow_glacier_block.unwrap_or_default(),
                gray_glacier_block: genesis.config.gray_glacier_block.unwrap_or_default(),
                merge_netsplit_block: genesis.config.merge_netsplit_block,
                merge_terminal_total_difficulty: genesis
                    .config
                    .terminal_total_difficulty
                    .unwrap_or_default()
                    .as_u128(),
                ..Default::default() // TODO: when paris_block is removed, remove this
            },
            genesis: Genesis {
                nonce: genesis.nonce.as_u64(),
                timestamp: genesis.timestamp.as_u64(),
                gas_limit: genesis.gas_limit.as_u64(),
                difficulty: genesis.difficulty.into(),
                mix_hash: genesis.mix_hash.0.into(),
                coinbase: genesis.coinbase.0.into(),
                extra_data: genesis.extra_data.0.into(),
                alloc,
            },
        }
    }
}

/// Clap value parser for [ChainSpecification]s that takes either a built-in chainspec or the path
/// to a custom one.
pub fn chain_spec_value_parser(s: &str) -> Result<ChainSpecification, eyre::Error> {
    Ok(match s {
        "mainnet" => {
            serde_json::from_str(include_str!("../../../../bin/reth/res/chainspec/mainnet.json"))?
        }
        "goerli" => {
            serde_json::from_str(include_str!("../../../../bin/reth/res/chainspec/goerli.json"))?
        }
        "sepolia" => {
            serde_json::from_str(include_str!("../../../../bin/reth/res/chainspec/sepolia.json"))?
        }
        _ => {
            let raw = std::fs::read_to_string(PathBuf::from(shellexpand::full(s)?.into_owned()))?;
            serde_json::from_str(&raw)?
        }
    })
}
