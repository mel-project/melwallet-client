use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use themelio_stf::melvm::Covenant;
use themelio_structs::{
    Address, BlockHeight, CoinData, CoinDataHeight, CoinID, CoinValue, NetID, StakeDoc,
    Transaction, TxHash,
};
use tmelcrypt::HashVal;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletSummary {
    pub total_micromel: CoinValue,
    pub detailed_balance: BTreeMap<String, CoinValue>,
    pub staked_microsym: CoinValue,
    pub network: NetID,
    #[serde(with = "stdcode::asstr")]
    pub address: Address,
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
    pub unspent_coins: BTreeMap<CoinID, CoinDataHeight>,
    #[serde_as(as = "Vec<(_, _)>")]
    pub spent_coins: BTreeMap<CoinID, CoinDataHeight>,
    #[serde(rename = "tx_in_progress_v2", default)]
    pub tx_in_progress: BTreeMap<TxHash, (Transaction, BlockHeight)>,
    pub tx_confirmed: BTreeMap<HashVal, (Transaction, BlockHeight)>,
    pub my_covenant: Covenant,
    #[serde(default)]
    pub stake_list: BTreeMap<TxHash, StakeDoc>,
    pub network: NetID,
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
