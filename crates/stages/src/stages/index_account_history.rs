use crate::{
    db::Transaction, ExecInput, ExecOutput, Stage, StageError, StageId, UnwindInput, UnwindOutput,
};
use itertools::Itertools;
use reth_db::{
    cursor::{DbCursorRO, DbCursorRW},
    database::Database,
    models::ShardedKey,
    tables,
    transaction::{DbTx, DbTxMut},
    TransitionList,
};
use reth_primitives::{Address, TransitionId};
use std::{collections::BTreeMap, fmt::Debug};
use tracing::*;

const INDEX_ACCOUNT_HISTORY: StageId = StageId("IndexAccountHistoryStage");

const NUM_OF_INDICES_IN_SHARD: usize = 100;
/// Account hashing stage hashes plain account.
/// This is preparation before generating intermediate hashes and calculating Merkle tree root.
#[derive(Debug)]
pub struct IndexAccountHistoryStage {
    /// Number of blocks after which the control
    /// flow will be returned to the pipeline for commit.
    pub commit_threshold: u64,
}

#[async_trait::async_trait]
impl<DB: Database> Stage<DB> for IndexAccountHistoryStage {
    /// Return the id of the stage
    fn id(&self) -> StageId {
        INDEX_ACCOUNT_HISTORY
    }

    /// Execute the stage.
    async fn execute(
        &mut self,
        tx: &mut Transaction<'_, DB>,
        input: ExecInput,
    ) -> Result<ExecOutput, StageError> {
        let stage_progress = input.stage_progress.unwrap_or_default();
        let previous_stage_progress = input.previous_stage_progress();

        // read account changeset, merge it into one changeset and calculate account hashes.
        let from_transition = tx.get_block_transition(stage_progress)? + 1;
        // NOTE: can probably done more probabilistic with transition but it is guess game for
        // later. Transitions better reflect how much data we are going to transfer.
        let to_block =
            std::cmp::min(stage_progress + self.commit_threshold, previous_stage_progress);
        let to_transition = tx.get_block_transition(to_block)? + 1;

        tx.cursor_read::<tables::AccountChangeSet>()?
            .walk(from_transition)?
            .take_while(|res| res.as_ref().map(|(k, _)| *k < to_transition).unwrap_or_default())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            // fold all account to one set of changed accounts
            .fold(BTreeMap::new(), |mut accounts: BTreeMap<Address, Vec<u64>>, (index, account)| {
                accounts.entry(account.address).or_default().push(index);
                accounts
            })
            .into_iter()
            // insert indexes to AccontHistory.
            .try_for_each(|(address, mut indices)| -> Result<(), StageError> {
                // load last shard and check if it is full, remove last shard and append indices.
                let indices = if let Some((shard_key, list)) =
                    tx.get_account_history_biggest_sharded_index(address)?
                {
                    if list.len() >= NUM_OF_INDICES_IN_SHARD {
                        // if latest shard is full, just append new indices
                        indices
                    } else {
                        // delete old shard so new one can be inserted.
                        tx.delete::<tables::AccountHistory>(shard_key, None)?;
                        let mut list = list.iter(0).map(|i| i as u64).collect::<Vec<_>>();
                        list.append(&mut indices);
                        list
                    }
                } else {
                    // if presently there isn't any shard insert all indices
                    indices
                };
                // chunk indices and insert them in shards of N size.
                indices.into_iter().chunks(NUM_OF_INDICES_IN_SHARD).into_iter().try_for_each(
                    |chuck| {
                        let list = chuck.map(|i| i as usize).collect::<Vec<_>>();
                        let biggest_id =
                            *list.last().expect("Chuck does not return empty list") as TransitionId;
                        let list =
                            TransitionList::new(list).expect("Indices are presorted and not empty");

                        tx.put::<tables::AccountHistory>(ShardedKey::new(address, biggest_id), list)
                    },
                )?;
                // get
                Ok(())
            })?;

        info!(target: "sync::stages::index_account_history", "Stage finished");
        Ok(ExecOutput { stage_progress: to_block, done: true })
    }

    /// Unwind the stage.
    async fn unwind(
        &mut self,
        tx: &mut Transaction<'_, DB>,
        input: UnwindInput,
    ) -> Result<UnwindOutput, StageError> {
        let from_transition_rev = tx.get_block_transition(input.unwind_to)? + 1;
        let to_transition_rev = tx.get_block_transition(input.stage_progress)? + 1;

        tx.cursor_read::<tables::AccountChangeSet>()?
            .walk(from_transition_rev)?
            .take_while(|res| res.as_ref().map(|(k, _)| *k < to_transition_rev).unwrap_or_default())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            // reverse so we can get lowest transition id where we need to unwind account.
            .rev()
            // fold all account and get last transition index
            .fold(BTreeMap::new(), |mut accounts: BTreeMap<Address, u64>, (index, account)| {
                // we just need address and lowest transition id.
                accounts.insert(account.address, index);
                accounts
            })
            .into_iter()
            // try to unwind the index
            .try_for_each(|(address, mut rem_index)| -> Result<(), StageError> {
                let mut cursor = tx.cursor_write::<tables::AccountHistory>()?;
                let mut last_shard = cursor.seek_exact(ShardedKey::new(address, u64::MAX))?;

                let mut boundary = None;
                while let Some((sharded_key, list)) = cursor.prev()? {
                    // there is no more shard for address
                    if sharded_key.key != address {
                        break;
                    }
                    // check first item and if it is more and eq than `rem_index` delete current
                    // item.
                    let first = list.successor(0).expect("List can't empty");
                    if first >= rem_index as usize {
                        cursor.delete_current()?;
                    } else if rem_index <= sharded_key.highest_transition_id {
                        // if eq, last element needs to be removed.
                        cursor.delete_current()?;
                        boundary = Some(list);
                        break;
                    } else {
                        break;
                    }
                }

                // check boundary, if present some items in current list needs to be removed.
                if let Some(old_list) = boundary {
                    let new_list = old_list
                        .iter(0)
                        .take_while(|i| *i < rem_index as usize)
                        .collect::<Vec<_>>();
                    // While loop above checks if first and last element [first, .., last]
                    // if first element is in scope whole list would be removed.
                    // so at least this first element is present.
                    let biggest_index =
                        *new_list.last().expect("There is at least one element in list");
                    let new_list = TransitionList::new(new_list)
                        .expect("There is at least one element in list and it is sorted.");
                    tx.put::<tables::AccountHistory>(
                        ShardedKey::new(address, biggest_index as u64),
                        new_list,
                    )?;
                }
                Ok(())
            })?;
        // from HistoryIndex higher than that number.
        Ok(UnwindOutput { stage_progress: input.unwind_to })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        stage_test_suite_ext, ExecuteStageTestRunner, TestRunnerError, UnwindStageTestRunner,
        PREV_STAGE_ID,
    };
    use assert_matches::assert_matches;
    use reth_db::{
        mdbx::{test_utils::create_test_db, EnvKind, WriteMap},
        models::AccountBeforeTx,
    };
    use reth_interfaces::test_utils::generators::random_block_range;
    use reth_primitives::{hex_literal::hex, Account, SealedBlock, H160, H256, U256};
    use reth_provider::insert_canonical_block;
    //use test_utils::*;

    #[tokio::test]
    async fn sanity_test() {
        // set BlockTransitionIndex for indexing changeset
        // set AccountChangeSet
        // set AccountHistory

        let state_db = create_test_db::<WriteMap>(EnvKind::RW);
        let mut tx = Transaction::new(state_db.as_ref()).unwrap();
        let input = ExecInput {
            previous_stage: Some((PREV_STAGE_ID, 1)),
            /// The progress of this stage the last time it was executed.
            stage_progress: None,
        };
        tx.put::<tables::BlockTransitionIndex>(1, 1).unwrap();
        tx.put::<tables::BlockTransitionIndex>(2, 3).unwrap();
        tx.put::<tables::BlockTransitionIndex>(3, 5).unwrap();

        // change does not matter only that account is present in changeset.
        let addr1 = H160(hex!("0000000000000000000000000000000000000001"));
        let addr2 = H160(hex!("0000000000000000000000000000000000000002"));

        let acc = |address: H160| -> AccountBeforeTx { AccountBeforeTx { address, info: None } };

        // setup changeset that are going to be applied to history index
        tx.put::<tables::AccountChangeSet>(1, acc(addr1)).unwrap();
        tx.put::<tables::AccountChangeSet>(1, acc(addr2)).unwrap();
        tx.put::<tables::AccountChangeSet>(2, acc(addr1)).unwrap();

        let list = |list: &[usize]| -> TransitionList { TransitionList::new(list).unwrap() };

        tx.put::<tables::AccountHistory>(ShardedKey::new(addr1, 3), list(&[0, 1, 3])).unwrap();
        tx.put::<tables::AccountHistory>(ShardedKey::new(addr2, 2), list(&[0, 1, 2])).unwrap();
    }

    /*
    stage_test_suite_ext!(AccountHashingTestRunner);

    #[tokio::test]
    async fn execute_below_clean_threshold() {
        let (previous_stage, stage_progress) = (20, 10);
        // Set up the runner
        let mut runner = AccountHashingTestRunner::default();
        runner.set_clean_threshold(1);

        let input = ExecInput {
            previous_stage: Some((PREV_STAGE_ID, previous_stage)),
            stage_progress: Some(stage_progress),
        };

        runner.seed_execution(input).expect("failed to seed execution");

        let rx = runner.execute(input);
        let result = rx.await.unwrap();

        assert_matches!(result, Ok(ExecOutput {done, stage_progress}) if done && stage_progress == previous_stage);

        // Validate the stage execution
        assert!(runner.validate_execution(input, result.ok()).is_ok(), "execution validation");
    }

    mod test_utils {
        use super::*;
        use crate::{
            stages::hashing_account::AccountHashingStage,
            test_utils::{StageTestRunner, TestTransaction},
            ExecInput, ExecOutput, UnwindInput,
        };
        use reth_db::{
            cursor::DbCursorRO,
            models::AccountBeforeTx,
            tables,
            transaction::{DbTx, DbTxMut},
        };
        use reth_interfaces::test_utils::generators::random_eoa_account_range;

        pub(crate) struct AccountHashingTestRunner {
            pub(crate) tx: TestTransaction,
            commit_threshold: u64,
            clean_threshold: u64,
        }

        impl AccountHashingTestRunner {
            pub(crate) fn set_clean_threshold(&mut self, threshold: u64) {
                self.clean_threshold = threshold;
            }

            #[allow(dead_code)]
            pub(crate) fn set_commit_threshold(&mut self, threshold: u64) {
                self.commit_threshold = threshold;
            }

            pub(crate) fn insert_blocks(
                &self,
                blocks: Vec<SealedBlock>,
            ) -> Result<(), TestRunnerError> {
                let mut blocks_iter = blocks.iter();
                while let Some(block) = blocks_iter.next() {
                    self.tx.commit(|tx| {
                        insert_canonical_block(tx, block, true).unwrap();
                        Ok(())
                    })?;
                }

                Ok(())
            }

            pub(crate) fn insert_accounts(
                &self,
                accounts: &Vec<(Address, Account)>,
            ) -> Result<(), TestRunnerError> {
                let mut accs_iter = accounts.iter();
                while let Some((addr, acc)) = accs_iter.next() {
                    self.tx.commit(|tx| {
                        tx.put::<tables::PlainAccountState>(*addr, *acc)?;
                        Ok(())
                    })?;
                }

                Ok(())
            }

            /// Iterates over PlainAccount table and checks that the accounts match the ones
            /// in the HashedAccount table
            pub(crate) fn check_hashed_accounts(&self) -> Result<(), TestRunnerError> {
                self.tx.query(|tx| {
                    let mut acc_cursor = tx.cursor_read::<tables::PlainAccountState>()?;
                    let mut hashed_acc_cursor = tx.cursor_read::<tables::HashedAccount>()?;

                    while let Some((address, account)) = acc_cursor.next()? {
                        let hashed_addr = keccak256(address);
                        if let Some((_, acc)) = hashed_acc_cursor.seek_exact(hashed_addr)? {
                            assert_eq!(acc, account)
                        }
                    }
                    Ok(())
                })?;

                Ok(())
            }

            /// Same as check_hashed_accounts, only that checks with the old account state,
            /// namely, the same account with nonce - 1 and balance - 1.
            pub(crate) fn check_old_hashed_accounts(&self) -> Result<(), TestRunnerError> {
                self.tx.query(|tx| {
                    let mut acc_cursor = tx.cursor_read::<tables::PlainAccountState>()?;
                    let mut hashed_acc_cursor = tx.cursor_read::<tables::HashedAccount>()?;

                    while let Some((address, account)) = acc_cursor.next()? {
                        let Account { nonce, balance, .. } = account;
                        let old_acc = Account {
                            nonce: nonce - 1,
                            balance: balance - U256::from(1),
                            bytecode_hash: None,
                        };
                        let hashed_addr = keccak256(address);
                        if let Some((_, acc)) = hashed_acc_cursor.seek_exact(hashed_addr)? {
                            assert_eq!(acc, old_acc)
                        }
                    }
                    Ok(())
                })?;

                Ok(())
            }
        }

        impl Default for AccountHashingTestRunner {
            fn default() -> Self {
                Self {
                    tx: TestTransaction::default(),
                    commit_threshold: 1000,
                    clean_threshold: 1000,
                }
            }
        }

        impl StageTestRunner for AccountHashingTestRunner {
            type S = AccountHashingStage;

            fn tx(&self) -> &TestTransaction {
                &self.tx
            }

            fn stage(&self) -> Self::S {
                Self::S {
                    commit_threshold: self.commit_threshold,
                    clean_threshold: self.clean_threshold,
                }
            }
        }

        #[async_trait::async_trait]
        impl ExecuteStageTestRunner for AccountHashingTestRunner {
            type Seed = Vec<(Address, Account)>;

            fn seed_execution(&mut self, input: ExecInput) -> Result<Self::Seed, TestRunnerError> {
                let end = input.previous_stage_progress() + 1;

                let blocks = random_block_range(0..end, H256::zero(), 0..3);
                self.insert_blocks(blocks)?;

                let n_accounts = 2;
                let accounts = random_eoa_account_range(&mut (0..n_accounts));
                self.insert_accounts(&accounts)?;

                // seed account changeset
                self.tx
                    .commit(|tx| {
                        let (_, last_transition) =
                            tx.cursor_read::<tables::BlockTransitionIndex>()?.last()?.unwrap();

                        let first_transition =
                            last_transition.checked_sub(n_accounts).unwrap_or_default();

                        for (t, (addr, acc)) in (first_transition..last_transition).zip(&accounts) {
                            let Account { nonce, balance, .. } = acc;
                            let prev_acc = Account {
                                nonce: nonce - 1,
                                balance: balance - U256::from(1),
                                bytecode_hash: None,
                            };
                            let acc_before_tx =
                                AccountBeforeTx { address: *addr, info: Some(prev_acc) };
                            tx.put::<tables::AccountChangeSet>(t, acc_before_tx)?;
                        }

                        Ok(())
                    })
                    .unwrap();

                Ok(accounts)
            }

            fn validate_execution(
                &self,
                input: ExecInput,
                output: Option<ExecOutput>,
            ) -> Result<(), TestRunnerError> {
                if let Some(output) = output {
                    let start_block = input.stage_progress.unwrap_or_default() + 1;
                    let end_block = output.stage_progress;
                    if start_block > end_block {
                        return Ok(());
                    }
                }
                self.check_hashed_accounts()
            }
        }

        impl UnwindStageTestRunner for AccountHashingTestRunner {
            fn validate_unwind(&self, _input: UnwindInput) -> Result<(), TestRunnerError> {
                self.check_old_hashed_accounts()
            }
        }
    }
     */
}
