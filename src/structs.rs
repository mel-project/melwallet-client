use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use themelio_stf::{
    melvm::{CovHash, Covenant},
    CoinData, CoinDataHeight, CoinID, NetID, Transaction,
};
use tmelcrypt::HashVal;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletSummary {
    pub total_micromel: u128,
    pub detailed_balance: BTreeMap<String, u128>,
    pub network: NetID,
    #[serde(with = "stdcode::asstr")]
    pub address: CovHash,
    pub locked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletDump {
    pub summary: WalletSummary,
    pub full: WalletData,
}

/// Immutable & cloneable in-memory data that can be persisted.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalletData {
    #[serde_as(as = "Vec<(_, _)>")]
    unspent_coins: BTreeMap<CoinID, CoinDataHeight>,
    #[serde_as(as = "Vec<(_, _)>")]
    spent_coins: BTreeMap<CoinID, CoinDataHeight>,
    tx_in_progress: BTreeMap<HashVal, Transaction>,
    tx_confirmed: BTreeMap<HashVal, (Transaction, u64)>,
    my_covenant: Covenant,
    network: NetID,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransactionStatus {
    pub raw: Transaction,
    pub confirmed_height: Option<u64>,
    pub outputs: Vec<AnnCoinID>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnnCoinID {
    pub coin_data: CoinData,
    pub is_change: bool,
    pub coin_id: String,
}
