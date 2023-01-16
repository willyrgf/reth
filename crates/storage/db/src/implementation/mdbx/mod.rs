//! Module that interacts with MDBX.

use crate::{
    database::{Database, DatabaseGAT},
    tables::{TableType, TABLES},
    utils::default_page_size,
    Error,
};
use reth_libmdbx::{
    DatabaseFlags, Environment, EnvironmentFlags, EnvironmentKind, Geometry, Mode, PageSize,
    SyncMode, RO, RW,
};
use std::{ops::Deref, path::Path};

pub mod cursor;

pub mod tx;
use tx::Tx;

/// Environment used when opening a MDBX environment. RO/RW.
#[derive(Debug)]
pub enum EnvKind {
    /// Read-only MDBX environment.
    RO,
    /// Read-write MDBX environment.
    RW,
}

/// Wrapper for the libmdbx environment.
#[derive(Debug)]
pub struct Env<E: EnvironmentKind> {
    /// Libmdbx-sys environment.
    pub inner: Environment<E>,
}

impl<'a, E: EnvironmentKind> DatabaseGAT<'a> for Env<E> {
    type TX = tx::Tx<'a, RO, E>;
    type TXMut = tx::Tx<'a, RW, E>;
}

impl<E: EnvironmentKind> Database for Env<E> {
    fn tx(&self) -> Result<<Self as DatabaseGAT<'_>>::TX, Error> {
        Ok(Tx::new(self.inner.begin_ro_txn().map_err(|e| Error::InitTransaction(e.into()))?))
    }

    fn tx_mut(&self) -> Result<<Self as DatabaseGAT<'_>>::TXMut, Error> {
        Ok(Tx::new(self.inner.begin_rw_txn().map_err(|e| Error::InitTransaction(e.into()))?))
    }
}

impl<E: EnvironmentKind> Env<E> {
    /// Opens the database at the specified path with the given `EnvKind`.
    ///
    /// It does not create the tables, for that call [`Env::create_tables`].
    pub fn open(path: &Path, kind: EnvKind) -> Result<Env<E>, Error> {
        let mode = match kind {
            EnvKind::RO => Mode::ReadOnly,
            EnvKind::RW => Mode::ReadWrite { sync_mode: SyncMode::Durable },
        };

        let env = Env {
            inner: Environment::new()
                .set_max_dbs(TABLES.len())
                .set_geometry(Geometry {
                    size: Some(0..(1024 * 1024 * 1024 * 1024 * 4)), // TODO: reevaluate (4 tb)
                    growth_step: Some(1024 * 1024 * 256),           // TODO: reevaluate (256 mb)
                    shrink_threshold: None,
                    page_size: Some(PageSize::Set(default_page_size())),
                })
                .set_flags(EnvironmentFlags {
                    mode,
                    no_rdahead: true, // TODO: reevaluate
                    coalesce: true,
                    ..Default::default()
                })
                .open(path)
                .map_err(|e| Error::DatabaseLocation(e.into()))?,
        };

        Ok(env)
    }

    /// Creates all the defined tables, if necessary.
    pub fn create_tables(&self) -> Result<(), Error> {
        let tx = self.inner.begin_rw_txn().map_err(|e| Error::InitTransaction(e.into()))?;

        for (table_type, table) in TABLES {
            let flags = match table_type {
                TableType::Table => DatabaseFlags::default(),
                TableType::DupSort => DatabaseFlags::DUP_SORT,
            };

            tx.create_db(Some(table), flags).map_err(|e| Error::TableCreation(e.into()))?;
        }

        tx.commit().map_err(|e| Error::Commit(e.into()))?;

        Ok(())
    }
}

impl<E: EnvironmentKind> Deref for Env<E> {
    type Target = reth_libmdbx::Environment<E>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Collection of database test utilities
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use super::{Env, EnvKind, EnvironmentKind, Path};
    use std::sync::Arc;

    /// Error during database creation
    pub const ERROR_DB_CREATION: &str = "Not able to create the mdbx file.";
    /// Error during table creation
    pub const ERROR_TABLE_CREATION: &str = "Not able to create tables in the database.";
    /// Error during tempdir creation
    pub const ERROR_TEMPDIR: &str = "Not able to create a temporary directory.";

    /// Create rw database for testing
    pub fn create_test_rw_db<E: EnvironmentKind>() -> Arc<Env<E>> {
        create_test_db(EnvKind::RW)
    }
    /// Create database for testing
    pub fn create_test_db<E: EnvironmentKind>(kind: EnvKind) -> Arc<Env<E>> {
        Arc::new(create_test_db_with_path(
            kind,
            &tempfile::TempDir::new().expect(ERROR_TEMPDIR).into_path(),
        ))
    }

    /// Create database for testing with specified path
    pub fn create_test_db_with_path<E: EnvironmentKind>(kind: EnvKind, path: &Path) -> Env<E> {
        let env = Env::<E>::open(path, kind).expect(ERROR_DB_CREATION);
        env.create_tables().expect(ERROR_TABLE_CREATION);
        env
    }
}

#[cfg(test)]
mod tests {
    use super::{test_utils, Env, EnvKind};
    use crate::{
        cursor::{DbCursorRO, DbCursorRW, DbDupCursorRO},
        database::Database,
        models::ShardedKey,
        tables::{AccountHistory, CanonicalHeaders, Headers, PlainAccountState, PlainStorageState},
        transaction::{DbTx, DbTxMut},
        Error,
    };
    use reth_libmdbx::{NoWriteMap, WriteMap};
    use reth_primitives::{Account, Address, Header, IntegerList, StorageEntry, H256, U256};
    use std::{str::FromStr, sync::Arc};
    use tempfile::TempDir;

    const ERROR_DB_CREATION: &str = "Not able to create the mdbx file.";
    const ERROR_PUT: &str = "Not able to insert value into table.";
    const ERROR_GET: &str = "Not able to get value from table.";
    const ERROR_COMMIT: &str = "Not able to commit transaction.";
    const ERROR_RETURN_VALUE: &str = "Mismatching result.";
    const ERROR_INIT_TX: &str = "Failed to create a MDBX transaction.";
    const ERROR_ETH_ADDRESS: &str = "Invalid address.";

    #[test]
    fn db_creation() {
        test_utils::create_test_db::<NoWriteMap>(EnvKind::RW);
    }

    #[test]
    fn db_manual_put_get() {
        let env = test_utils::create_test_db::<NoWriteMap>(EnvKind::RW);

        let value = Header::default();
        let key = (1u64, H256::zero());

        // PUT
        let tx = env.tx_mut().expect(ERROR_INIT_TX);
        tx.put::<Headers>(key.into(), value.clone()).expect(ERROR_PUT);
        tx.commit().expect(ERROR_COMMIT);

        // GET
        let tx = env.tx().expect(ERROR_INIT_TX);
        let result = tx.get::<Headers>(key.into()).expect(ERROR_GET);
        assert!(result.expect(ERROR_RETURN_VALUE) == value);
        tx.commit().expect(ERROR_COMMIT);
    }

    #[test]
    fn db_cursor_walk() {
        let env = test_utils::create_test_db::<NoWriteMap>(EnvKind::RW);

        let value = Header::default();
        let key = (1u64, H256::zero());

        // PUT
        let tx = env.tx_mut().expect(ERROR_INIT_TX);
        tx.put::<Headers>(key.into(), value.clone()).expect(ERROR_PUT);
        tx.commit().expect(ERROR_COMMIT);

        // Cursor
        let tx = env.tx().expect(ERROR_INIT_TX);
        let mut cursor = tx.cursor_read::<Headers>().unwrap();

        let first = cursor.first().unwrap();
        assert!(first.is_some(), "First should be our put");

        // Walk
        let walk = cursor.walk(key.into()).unwrap();
        let first = walk.into_iter().next().unwrap().unwrap();
        assert_eq!(first.1, value, "First next should be put value");
    }

    #[test]
    fn db_cursor_seek_exact_or_previous_key() {
        let db: Arc<Env<WriteMap>> = test_utils::create_test_db(EnvKind::RW);

        // PUT
        let tx = db.tx_mut().expect(ERROR_INIT_TX);
        vec![0, 1, 3]
            .into_iter()
            .try_for_each(|key| tx.put::<CanonicalHeaders>(key, H256::zero()))
            .expect(ERROR_PUT);
        tx.commit().expect(ERROR_COMMIT);

        // Cursor
        let missing_key = 2;
        let tx = db.tx().expect(ERROR_INIT_TX);
        let mut cursor = tx.cursor_read::<CanonicalHeaders>().unwrap();
        assert_eq!(cursor.current(), Ok(None));

        // Seek exact
        let exact = cursor.seek_exact(missing_key).unwrap();
        assert_eq!(exact, None);
        assert_eq!(cursor.current(), Ok(Some((missing_key + 1, H256::zero()))));
        assert_eq!(cursor.prev(), Ok(Some((missing_key - 1, H256::zero()))));
        assert_eq!(cursor.prev(), Ok(Some((missing_key - 2, H256::zero()))));
    }

    #[test]
    fn db_cursor_insert() {
        let db: Arc<Env<WriteMap>> = test_utils::create_test_db(EnvKind::RW);

        // PUT
        let tx = db.tx_mut().expect(ERROR_INIT_TX);
        vec![0, 1, 3, 4, 5]
            .into_iter()
            .try_for_each(|key| tx.put::<CanonicalHeaders>(key, H256::zero()))
            .expect(ERROR_PUT);
        tx.commit().expect(ERROR_COMMIT);

        let db: Arc<Env<WriteMap>> = test_utils::create_test_db(EnvKind::RW);

        let key_to_insert = 2;
        let tx = db.tx_mut().expect(ERROR_INIT_TX);
        let mut cursor = tx.cursor_write::<CanonicalHeaders>().unwrap();

        // INSERT
        cursor.seek_exact(1).unwrap();
        assert_eq!(cursor.insert(key_to_insert, H256::zero()), Ok(()));
        assert_eq!(cursor.current(), Ok(Some((key_to_insert, H256::zero()))));

        // INSERT (failure)
        assert_eq!(cursor.insert(key_to_insert, H256::zero()), Err(Error::Write(4294936497)));
        assert_eq!(cursor.current(), Ok(Some((key_to_insert, H256::zero()))));
    }

    #[test]
    fn db_cursor_append_failure() {
        let db: Arc<Env<WriteMap>> = test_utils::create_test_db(EnvKind::RW);

        // PUT
        let tx = db.tx_mut().expect(ERROR_INIT_TX);
        vec![0, 1, 3, 4, 5]
            .into_iter()
            .try_for_each(|key| tx.put::<CanonicalHeaders>(key, H256::zero()))
            .expect(ERROR_PUT);
        tx.commit().expect(ERROR_COMMIT);

        // APPEND
        let key_to_append = 2;
        let tx = db.tx_mut().expect(ERROR_INIT_TX);
        let mut cursor = tx.cursor_write::<CanonicalHeaders>().unwrap();
        cursor.seek_exact(1).unwrap();
        assert_eq!(cursor.append(key_to_append, H256::zero()), Err(Error::Write(4294936878)));
        assert_eq!(cursor.current(), Ok(Some((5, H256::zero())))); // the end of table
    }

    #[test]
    fn db_closure_put_get() {
        let path = TempDir::new().expect(test_utils::ERROR_TEMPDIR).into_path();

        let value = Account {
            nonce: 18446744073709551615,
            bytecode_hash: Some(H256::random()),
            balance: U256::MAX,
        };
        let key = Address::from_str("0xa2c122be93b0074270ebee7f6b7292c7deb45047")
            .expect(ERROR_ETH_ADDRESS);

        {
            let env = test_utils::create_test_db_with_path::<WriteMap>(EnvKind::RW, &path);

            // PUT
            let result = env.update(|tx| {
                tx.put::<PlainAccountState>(key, value).expect(ERROR_PUT);
                200
            });
            assert!(result.expect(ERROR_RETURN_VALUE) == 200);
        }

        let env = Env::<WriteMap>::open(&path, EnvKind::RO).expect(ERROR_DB_CREATION);

        // GET
        let result =
            env.view(|tx| tx.get::<PlainAccountState>(key).expect(ERROR_GET)).expect(ERROR_GET);

        assert!(result == Some(value))
    }

    #[test]
    fn db_dup_sort() {
        let env = test_utils::create_test_db::<NoWriteMap>(EnvKind::RW);
        let key = Address::from_str("0xa2c122be93b0074270ebee7f6b7292c7deb45047")
            .expect(ERROR_ETH_ADDRESS);

        // PUT (0,0)
        let value00 = StorageEntry::default();
        env.update(|tx| tx.put::<PlainStorageState>(key, value00.clone()).expect(ERROR_PUT))
            .unwrap();

        // PUT (2,2)
        let value22 = StorageEntry { key: H256::from_low_u64_be(2), value: U256::from(2) };
        env.update(|tx| tx.put::<PlainStorageState>(key, value22.clone()).expect(ERROR_PUT))
            .unwrap();

        // PUT (1,1)
        let value11 = StorageEntry { key: H256::from_low_u64_be(1), value: U256::from(1) };
        env.update(|tx| tx.put::<PlainStorageState>(key, value11.clone()).expect(ERROR_PUT))
            .unwrap();

        // Iterate with cursor
        {
            let tx = env.tx().expect(ERROR_INIT_TX);
            let mut cursor = tx.cursor_dup_read::<PlainStorageState>().unwrap();

            // Notice that value11 and value22 have been ordered in the DB.
            assert!(Some(value00) == cursor.next_dup_val().unwrap());
            assert!(Some(value11.clone()) == cursor.next_dup_val().unwrap());
            assert!(Some(value22) == cursor.next_dup_val().unwrap());
        }

        // Seek value with exact subkey
        {
            let tx = env.tx().expect(ERROR_INIT_TX);
            let mut cursor = tx.cursor_dup_read::<PlainStorageState>().unwrap();
            let mut walker = cursor.walk_dup(key, H256::from_low_u64_be(1)).unwrap();
            assert_eq!(
                (key, value11),
                walker
                    .next()
                    .expect("element should exist.")
                    .expect("should be able to retrieve it.")
            );
        }
    }

    #[test]
    fn db_iterate_over_all_dup_values() {
        let env = test_utils::create_test_db::<NoWriteMap>(EnvKind::RW);
        let key1 = Address::from_str("0x1111111111111111111111111111111111111111")
            .expect(ERROR_ETH_ADDRESS);
        let key2 = Address::from_str("0x2222222222222222222222222222222222222222")
            .expect(ERROR_ETH_ADDRESS);

        // PUT key1 (0,0)
        let value00 = StorageEntry::default();
        env.update(|tx| tx.put::<PlainStorageState>(key1, value00.clone()).expect(ERROR_PUT))
            .unwrap();

        // PUT key1 (1,1)
        let value11 = StorageEntry { key: H256::from_low_u64_be(1), value: U256::from(1) };
        env.update(|tx| tx.put::<PlainStorageState>(key1, value11.clone()).expect(ERROR_PUT))
            .unwrap();

        // PUT key2 (2,2)
        let value22 = StorageEntry { key: H256::from_low_u64_be(2), value: U256::from(2) };
        env.update(|tx| tx.put::<PlainStorageState>(key2, value22.clone()).expect(ERROR_PUT))
            .unwrap();

        // Iterate with walk_dup
        {
            let tx = env.tx().expect(ERROR_INIT_TX);
            let mut cursor = tx.cursor_dup_read::<PlainStorageState>().unwrap();
            let first = cursor.first().unwrap().unwrap();
            let mut walker = cursor.walk_dup(first.0, first.1.key).unwrap();

            // Notice that value11 and value22 have been ordered in the DB.
            assert_eq!(Some(Ok((key1, value00.clone()))), walker.next());
            assert_eq!(Some(Ok((key1, value11.clone()))), walker.next());
            // NOTE: Dup cursor does NOT iterates on all values but only on duplicated values of the
            // same key. assert_eq!(Ok(Some(value22.clone())), walker.next());
            assert_eq!(None, walker.next());
        }

        // Iterate by using `walk`
        {
            let tx = env.tx().expect(ERROR_INIT_TX);
            let mut cursor = tx.cursor_dup_read::<PlainStorageState>().unwrap();
            let first = cursor.first().unwrap().unwrap();
            let mut walker = cursor.walk(first.0).unwrap();
            assert_eq!(Some(Ok((key1, value00))), walker.next());
            assert_eq!(Some(Ok((key1, value11))), walker.next());
            assert_eq!(Some(Ok((key2, value22))), walker.next());
        }
    }

    #[test]
    fn dup_value_with_same_subkey() {
        let env = test_utils::create_test_db::<NoWriteMap>(EnvKind::RW);
        let key1 = Address::from_str("0x1111111111111111111111111111111111111111")
            .expect(ERROR_ETH_ADDRESS);

        // PUT key1 (0,1)
        let value01 = StorageEntry { key: H256::from_low_u64_be(0), value: U256::from(1) };
        env.update(|tx| tx.put::<PlainStorageState>(key1, value01.clone()).expect(ERROR_PUT))
            .unwrap();

        // PUT key1 (0,0)
        let value00 = StorageEntry::default();
        env.update(|tx| tx.put::<PlainStorageState>(key1, value00.clone()).expect(ERROR_PUT))
            .unwrap();

        // Iterate with walk
        {
            let tx = env.tx().expect(ERROR_INIT_TX);
            let mut cursor = tx.cursor_dup_read::<PlainStorageState>().unwrap();
            let first = cursor.first().unwrap().unwrap();
            let mut walker = cursor.walk(first.0).unwrap();

            // NOTE: Both values are present
            assert_eq!(Some(Ok((key1, value00.clone()))), walker.next());
            assert_eq!(Some(Ok((key1, value01))), walker.next());
            assert_eq!(None, walker.next());
        }

        // seek_by_key_subkey
        {
            let tx = env.tx().expect(ERROR_INIT_TX);
            let mut cursor = tx.cursor_dup_read::<PlainStorageState>().unwrap();

            // NOTE: There are two values with same SubKey but only first one is shown
            assert_eq!(Ok(Some(value00.clone())), cursor.seek_by_key_subkey(key1, value00.key));
        }
    }

    #[test]
    fn db_sharded_key() {
        let db: Arc<Env<WriteMap>> = test_utils::create_test_db(EnvKind::RW);
        let real_key = Address::from_str("0xa2c122be93b0074270ebee7f6b7292c7deb45047").unwrap();

        for i in 1..5 {
            let key = ShardedKey::new(real_key, i * 100);
            let list: IntegerList = vec![i * 100u64].into();

            db.update(|tx| tx.put::<AccountHistory>(key.clone(), list.clone()).expect("")).unwrap();
        }

        // Seek value with non existing key.
        {
            let tx = db.tx().expect(ERROR_INIT_TX);
            let mut cursor = tx.cursor_read::<AccountHistory>().unwrap();

            // It will seek the one greater or equal to the query. Since we have `Address | 100`,
            // `Address | 200` in the database and we're querying `Address | 150` it will return us
            // `Address | 200`.
            let mut walker = cursor.walk(ShardedKey::new(real_key, 150)).unwrap();
            let (key, list) = walker
                .next()
                .expect("element should exist.")
                .expect("should be able to retrieve it.");

            assert_eq!(ShardedKey::new(real_key, 200), key);
            let list200: IntegerList = vec![200u64].into();
            assert_eq!(list200, list);
        }
        // Seek greatest index
        {
            let tx = db.tx().expect(ERROR_INIT_TX);
            let mut cursor = tx.cursor_read::<AccountHistory>().unwrap();

            // It will seek the MAX value of transition index and try to use prev to get first
            // biggers.
            let _unknown = cursor.seek_exact(ShardedKey::new(real_key, u64::MAX)).unwrap();
            let (key, list) = cursor
                .prev()
                .expect("element should exist.")
                .expect("should be able to retrieve it.");

            assert_eq!(ShardedKey::new(real_key, 400), key);
            let list400: IntegerList = vec![400u64].into();
            assert_eq!(list400, list);
        }
    }
}
