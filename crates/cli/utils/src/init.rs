use reth_db::{
    cursor::DbCursorRO,
    database::Database,
    mdbx::{Env, WriteMap},
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_primitives::{Account, Genesis, Header, H256};
use std::{path::Path, sync::Arc};
use tracing::debug;

/// Opens up an existing database or creates a new one at the specified path.
pub fn init_db<P: AsRef<Path>>(path: P) -> eyre::Result<Env<WriteMap>> {
    std::fs::create_dir_all(path.as_ref())?;
    let db = reth_db::mdbx::Env::<reth_db::mdbx::WriteMap>::open(
        path.as_ref(),
        reth_db::mdbx::EnvKind::RW,
    )?;
    db.create_tables()?;

    Ok(db)
}

/// Write the genesis block if it has not already been written
#[allow(clippy::field_reassign_with_default)]
pub fn init_genesis<DB: Database>(db: Arc<DB>, genesis: Genesis) -> Result<H256, reth_db::Error> {
    let tx = db.tx()?;
    if let Some((_, hash)) = tx.cursor_read::<tables::CanonicalHeaders>()?.first()? {
        debug!("Genesis already written, skipping.");
        return Ok(hash)
    }
    drop(tx);
    debug!("Writing genesis block.");
    let tx = db.tx_mut()?;

    // Insert account state
    for (address, account) in &genesis.alloc {
        tx.put::<tables::PlainAccountState>(
            *address,
            Account {
                nonce: account.nonce.unwrap_or_default(),
                balance: account.balance,
                bytecode_hash: None,
            },
        )?;
    }

    // Insert header
    let header: Header = genesis.into();
    let hash = header.hash_slow();
    tx.put::<tables::CanonicalHeaders>(0, hash)?;
    tx.put::<tables::HeaderNumbers>(hash, 0)?;
    tx.put::<tables::BlockBodies>((0, hash).into(), Default::default())?;
    tx.put::<tables::BlockTransitionIndex>((0, hash).into(), 0)?;
    tx.put::<tables::HeaderTD>((0, hash).into(), header.difficulty.into())?;
    tx.put::<tables::Headers>((0, hash).into(), header)?;

    tx.commit()?;
    Ok(hash)
}
