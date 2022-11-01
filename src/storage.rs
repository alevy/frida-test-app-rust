use std::path::Path;
use lmdb::{Transaction, WriteFlags};
use serde::{de::DeserializeOwned, Serialize};

pub const STORAGE_FILE: &'static str = "storage.db";

pub struct DB {
    dbenv: lmdb::Environment,
    db: lmdb::Database,
}

impl DB {
    pub fn new(path: &Path) -> Result<DB, lmdb::Error> {
        let dbenv = lmdb::Environment::new()
            .set_flags(lmdb::EnvironmentFlags::NO_SUB_DIR)
            .open(path)?;
        let db = dbenv.open_db(None)?;
        Ok(DB {
            dbenv, db
        })
    }

    pub fn get_item<K: AsRef<[u8]>, R: DeserializeOwned>(&self, key: K) -> Result<R, Box<dyn std::error::Error>> {
        let txn = self.dbenv.begin_ro_txn()?;
        let result = txn.get(self.db, &key)?;
        let result = serde_json::from_slice(result)?;
        txn.commit()?;
        Ok(result)
    }

    pub fn set_item<K: AsRef<[u8]>, V: Serialize>(&self, key: K, value: V) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = self.dbenv.begin_rw_txn()?;
        txn.put(
            self.db,
            &key,
            &serde_json::to_vec(&value)?,
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn delete_item<K: AsRef<[u8]>>(&self, key: K) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = self.dbenv.begin_rw_txn()?;
        txn.del(
            self.db,
            &key, None
        )?;
        txn.commit()?;
        Ok(())
    }
}
