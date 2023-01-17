//! Reth block execution/validation configuration and constants
use reth_executor::{Config as ExecutorConfig, SpecUpgrades};
use reth_primitives::{BlockNumber, U256};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Initial base fee as defined in: https://eips.ethereum.org/EIPS/eip-1559
pub const EIP1559_INITIAL_BASE_FEE: u64 = 1_000_000_000;
/// Base fee max change denominator as defined in: https://eips.ethereum.org/EIPS/eip-1559
pub const EIP1559_BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8;
/// Elasticity multiplier as defined in: https://eips.ethereum.org/EIPS/eip-1559
pub const EIP1559_ELASTICITY_MULTIPLIER: u64 = 2;

/// Common configuration for consensus algorithms.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Config {
    /// Blockchain identifier introduced in EIP-155: Simple replay attack protection.
    pub chain_id: u64,

    /// Homestead switch block.
    pub homestead_block: BlockNumber,

    /// TheDAO hard-fork switch block.
    pub dao_fork_block: BlockNumber,
    /// Whether the node supports or opposes the DAO hard-fork
    pub dao_fork_support: bool,

    /// EIP150 implements gas price changes.
    pub eip_150_block: BlockNumber,

    /// EIP155 hard-fork block (Spurious Dragon)
    pub eip_155_block: BlockNumber,
    /// EIP158 hard-fork block.
    pub eip_158_block: BlockNumber,
    /// Byzantium switch block.
    pub byzantium_block: BlockNumber,
    /// Constantinople switch block.
    pub constantinople_block: BlockNumber,
    /// Petersburg switch block.
    pub petersburg_block: BlockNumber,
    /// Istanbul switch block.
    pub istanbul_block: BlockNumber,
    /// Muir Glacier switch block.
    pub muir_glacier_block: BlockNumber,
    /// EIP-2728 switch block.
    pub berlin_block: BlockNumber,
    /// EIP-1559 switch block.
    pub london_block: BlockNumber,
    /// Arrow Glacier switch block.
    pub arrow_glacier_block: BlockNumber,
    /// Gray Glacier switch block.
    pub gray_glacier_block: BlockNumber,
    /// The Merge Netsplit switch block.
    pub merge_netsplit_block: Option<BlockNumber>,
    /// The Merge/Paris hard-fork block number.
    pub paris_block: BlockNumber,
    /// Terminal total difficulty after the paris hard-fork to reach before The Merge is considered
    /// activated.
    #[cfg_attr(feature = "serde", serde(rename = "terminalTotalDifficulty"))]
    pub merge_terminal_total_difficulty: u128,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: 1,
            homestead_block: 1150000,
            dao_fork_block: 1920000,
            dao_fork_support: true,
            eip_150_block: 2463000,
            eip_155_block: 2675000,
            eip_158_block: 2675000,
            byzantium_block: 4370000,
            constantinople_block: 7280000,
            petersburg_block: 7280000,
            istanbul_block: 9069000,
            muir_glacier_block: 9200000,
            berlin_block: 12244000,
            london_block: 12965000,
            arrow_glacier_block: 13773000,
            gray_glacier_block: 15050000,
            paris_block: 15537394,
            merge_terminal_total_difficulty: 58750000000000000000000,
            merge_netsplit_block: None,
        }
    }
}

impl From<&Config> for ExecutorConfig {
    fn from(value: &Config) -> Self {
        Self {
            chain_id: U256::from(value.chain_id),
            spec_upgrades: SpecUpgrades {
                frontier: 0,
                homestead: value.homestead_block,
                dao_fork: value.dao_fork_block,
                tangerine_whistle: value.eip_150_block,
                spurious_dragon: value.eip_158_block,
                byzantium: value.byzantium_block,
                petersburg: value.petersburg_block,
                istanbul: value.istanbul_block,
                berlin: value.berlin_block,
                london: value.london_block,
                paris: value.paris_block,
                shanghai: u64::MAX, // TODO: change once known
            },
        }
    }
}

impl Config {
    /// Obtains the list of the config's fork block numbers in order of activation.
    /// This only lists forks that were activated by block number, with a notable exception being
    /// the merge, also known as Paris.
    ///
    /// This should be the same as [Geth's `gather_forks`
    /// method](https://github.com/ethereum/go-ethereum/blob/6c149fd4ad063f7c24d726a73bc0546badd1bc73/core/forkid/forkid.go#L215).
    pub fn fork_blocks(&self) -> Vec<BlockNumber> {
        // will just put each consecutive fork in a vec
        // do NOT put paris into this vec, as it was not activated by block number.
        let mut fork_blocks_opt: Vec<Option<u64>> = vec![
            self.homestead_block.into(),
            self.dao_fork_block.into(),
            self.eip_150_block.into(),
            self.eip_155_block.into(),
            self.eip_158_block.into(),
            self.byzantium_block.into(),
            self.constantinople_block.into(),
            self.petersburg_block.into(),
            self.istanbul_block.into(),
            self.muir_glacier_block.into(),
            self.berlin_block.into(),
            self.london_block.into(),
            self.arrow_glacier_block.into(),
            self.gray_glacier_block.into(),
            self.merge_netsplit_block,
            // TODO: when cancun time is known
            // self.cancun_time,
            // TODO: when shangai time is known
            // self.shanghai_time,
        ];

        // filter out the None values
        fork_blocks_opt.retain(|block| block.is_some());

        // safely use unwrap (the vec is now guaranteed to have no None values)
        let mut fork_blocks: Vec<u64> =
            fork_blocks_opt.iter().map(|block| block.unwrap()).collect();

        // Sort the fork block numbers to permit chronological XOR
        fork_blocks.sort();

        // Deduplicate block numbers applying multiple forks (each block number should only be
        // represented once)
        fork_blocks_opt.dedup();

        // Skip any forks in block 0, that's the genesis ruleset
        fork_blocks.retain(|block| *block != 0);
        fork_blocks
    }
}
