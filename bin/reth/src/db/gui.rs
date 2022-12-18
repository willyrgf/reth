#![allow(dead_code, unreachable_pub)]
use reth_db::database::Database;

pub struct Gui<'a, DB: Database> {
    db: &'a DB,
}

impl<'a, DB: Database> Gui<'a, DB> {
    pub fn new(db: &'a DB) -> Self {
        Self { db }
    }

    pub async fn run(&self) -> eyre::Result<()> {
        Ok(())
    }
}
