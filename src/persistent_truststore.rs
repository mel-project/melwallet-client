use anyhow::Context;
use melstructs::{Checkpoint, NetID};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use melprot::TrustStore;
pub struct PersistentTrustStore {
    file_path: String,
    inner: Arc<RwLock<HashMap<NetID, Checkpoint>>>,
}

impl PersistentTrustStore {
    pub fn new(file_path: &str) -> anyhow::Result<Self> {
        let inner = if Path::new(file_path).exists() {
            let contents = std::fs::read(file_path).context("could not read trust store file")?;
            match serde_json::from_slice::<HashMap<NetID, Checkpoint>>(&contents) {
                Ok(data) => Arc::new(RwLock::new(data)),
                Err(err) => {
                    eprintln!("Initializing trust store with empty data");
                    Arc::new(RwLock::new(HashMap::new()))
                }
            }
        } else {
            Arc::new(RwLock::new(HashMap::new()))
        };

        Ok(Self {
            file_path: file_path.to_string(),
            inner,
        })
    }
}

impl TrustStore for PersistentTrustStore {
    fn set(&self, netid: NetID, trusted: Checkpoint) {
        let mut inner = self.inner.write().unwrap();
        if let Some(old) = inner.get(&netid) {
            if old.height >= trusted.height {
                return;
            }
        }
        inner.insert(netid, trusted);
        std::fs::write(
            &self.file_path,
            serde_json::to_string(&inner.clone()).unwrap(),
        )
        .unwrap();
    }

    fn get(&self, netid: NetID) -> Option<Checkpoint> {
        self.inner.read().unwrap().get(&netid).cloned()
    }
}
