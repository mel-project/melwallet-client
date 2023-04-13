use std::{collections::BTreeMap, path::Path};

use acidjson::AcidJson;
use base32::Alphabet;
use bytes::Bytes;
use melprot::{Client, CoinChange};
use melstructs::{
    Address, BlockHeight, CoinData, CoinID, CoinValue, Denom, Header, NetID, PoolKey, PoolState,
    Transaction, TxHash, TxKind,
};
use melwallet::{PrepareTxArgs, StdEd25519Signer, Wallet};
use serde::{Deserialize, Serialize};
use smol::stream::StreamExt;
use tmelcrypt::Ed25519SK;

use crate::cli::CoinDataWrapper;

#[derive(Serialize, Deserialize)]
pub struct WalletWithKey {
    pub wallet: Wallet,
    pub secret_key: Ed25519SK,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Summary of the entire wallet
pub struct WalletSummary {
    /// Detailed balance. Keys are the standard (Display/FromStr) string representation of a [Denom].
    pub detailed_balances: BTreeMap<Denom, CoinValue>,
    /// Staked SYM
    pub staked_microsym: CoinValue,
    /// Network ID (mainnet, testnet, etc). JSON-serialized as the corresponding integer.
    pub netid: NetID,
    /// Address of this wallet. JSON-serialized as the standard `t.....` address format.
    #[serde(with = "stdcode::asstr")]
    pub address: Address,
}
pub struct State {
    wwk: AcidJson<WalletWithKey>,
    melclient: melprot::Client,
}

impl State {
    /// Opens wallet at given path (assumes the wallet exists)
    /// and creates a melclient
    pub async fn new(wallet_path: &str) -> anyhow::Result<Self> {
        let wwk: AcidJson<WalletWithKey> = AcidJson::open(&Path::new(wallet_path))?;
        let netid = wwk.read().wallet.netid;
        let melclient = Client::autoconnect(netid).await?;
        Ok(Self { wwk, melclient })
    }

    pub async fn wallet_summary(&self) -> anyhow::Result<WalletSummary> {
        let wallet = &self.wwk.read().wallet;
        let summary = WalletSummary {
            detailed_balances: wallet.balances().clone(),
            staked_microsym: Default::default(), // staking not yet implemented
            netid: wallet.netid,
            address: wallet.address,
        };
        Ok(summary)
    }

    pub async fn prepare_faucet_tx(&self) -> anyhow::Result<Transaction> {
        let netid = self.wwk.read().wallet.netid;
        if netid == NetID::Mainnet {
            anyhow::bail!("faucets don't work on mainnet")
        }
        // construct the tx
        let tx = Transaction {
            kind: TxKind::Faucet,
            inputs: vec![],
            outputs: vec![CoinData {
                covhash: self.wwk.read().wallet.address,
                value: CoinValue::from_millions(1001u64),
                denom: Denom::Mel,
                additional_data: vec![].into(),
            }],
            data: (0..32).map(|_| fastrand::u8(0..=255)).collect(),
            fee: CoinValue::from_millions(1001u64),
            covenants: vec![],
            sigs: vec![],
        };
        Ok(tx)
    }

    pub async fn prepare_send_tx(
        &self,
        to: Vec<CoinDataWrapper>,
        force_spend: Vec<CoinID>,
        add_covenant: Vec<String>,
        hex_data: String,
        fee_ballast: usize,
    ) -> anyhow::Result<Transaction> {
        let inputs = {
            let mut v = vec![];
            let wallet_height = self.wwk.read().wallet.height;
            let snapshot = self.melclient.snapshot(wallet_height).await?;
            for id in force_spend {
                if let Some(cdh) = snapshot.get_coin(id).await? {
                    v.push((id, cdh));
                }
            }
            v
        };
        let desired_outputs = to.iter().map(|v| v.0.clone()).collect::<Vec<_>>();

        let cov: Vec<Bytes> = add_covenant
            .into_iter()
            .map(|s| hex::decode(&s).unwrap().into())
            .collect();

        let args = PrepareTxArgs {
            kind: melstructs::TxKind::Normal,
            inputs,
            outputs: desired_outputs,
            covenants: cov,
            data: hex::decode(&hex_data)?.into(),
            fee_ballast,
        };

        let tx = self.prepare_tx(args).await?;
        Ok(tx)
    }

    pub async fn prepare_swap_tx(
        &self,
        value: CoinValue,
        from: Denom,
        to: Denom,
    ) -> anyhow::Result<Transaction> {
        let pool_key = PoolKey::new(from, to);
        let ptx_args = PrepareTxArgs {
            kind: TxKind::Swap,
            inputs: vec![],
            outputs: vec![CoinData {
                value,
                denom: from,
                additional_data: vec![].into(),
                covhash: self.wwk.read().wallet.address,
            }],
            covenants: vec![],
            data: pool_key.to_bytes().into(),
            fee_ballast: 0,
        };
        let tx = self.prepare_tx(ptx_args).await?;

        Ok(tx)
    }

    pub async fn swap_to_value(
        &self,
        value: CoinValue,
        from: Denom,
        to: Denom,
    ) -> anyhow::Result<u128> {
        let pool_key = PoolKey::new(from, to);
        let pool_state = self.pool_info(pool_key).await?;
        let to_value = if from == pool_key.right() {
            pool_state.clone().swap_many(0, value.0).0
        } else {
            pool_state.clone().swap_many(value.0, 0).1
        };
        Ok(to_value)
    }

    pub async fn prepare_liq_deposit_tx(
        &self,
        a_count: CoinValue,
        a_denom: Denom,
        b_count: CoinValue,
        b_denom: Denom,
    ) -> anyhow::Result<Transaction> {
        // prepare tx
        let poolkey = PoolKey::new(a_denom, b_denom);
        let left_denom = poolkey.left();
        let right_denom = poolkey.right();
        let left_count = if left_denom == a_denom {
            a_count
        } else {
            b_count
        };
        let right_count = if right_denom == a_denom {
            a_count
        } else {
            b_count
        };

        let ptx_args = PrepareTxArgs {
            kind: TxKind::LiqDeposit,
            inputs: vec![],
            outputs: vec![
                CoinData {
                    value: left_count,
                    denom: left_denom,
                    covhash: self.wwk.read().wallet.address,
                    additional_data: vec![].into(),
                },
                CoinData {
                    value: right_count,
                    denom: right_denom,
                    covhash: self.wwk.read().wallet.address,
                    additional_data: vec![].into(),
                },
            ],
            covenants: vec![],
            data: poolkey.to_bytes().into(),
            fee_ballast: 0,
        };

        let tx = self.prepare_tx(ptx_args).await?;

        Ok(tx)
    }

    async fn prepare_tx(&self, args: PrepareTxArgs) -> anyhow::Result<Transaction> {
        let signer = StdEd25519Signer(self.wwk.read().secret_key);
        let fee_multiplier = self
            .melclient
            .latest_snapshot()
            .await?
            .current_header()
            .fee_multiplier;
        let tx = self
            .wwk
            .read()
            .wallet
            .prepare_tx(args, &signer, fee_multiplier)?;
        Ok(tx)
    }

    pub async fn send_raw(&self, tx: Transaction) -> anyhow::Result<()> {
        let _ = self
            .melclient
            .latest_snapshot()
            .await?
            .get_raw()
            .send_tx(tx.clone())
            .await?;
        self.wwk.write().wallet.add_pending(tx);

        Ok(())
    }

    /// true if the tx has completed
    pub fn tx_completed(&self, txhash: TxHash) -> bool {
        self.wwk
            .read()
            .wallet
            .pending_outgoing
            .get(&txhash)
            .is_none()
    }

    pub fn export_sk(&self) -> anyhow::Result<String> {
        let secret = self.wwk.read().secret_key;
        let sk: String = base32::encode(Alphabet::Crockford, &secret.0[..32]);
        Ok(sk)
    }

    pub async fn pool_info(&self, poolkey: PoolKey) -> anyhow::Result<PoolState> {
        if let Some(pool_state) = self
            .melclient
            .latest_snapshot()
            .await?
            .get_pool(poolkey)
            .await?
        {
            Ok(pool_state)
        } else {
            anyhow::bail!(
                "No pool for {}/{} could be found!",
                poolkey.left(),
                poolkey.right()
            );
        }
    }

    pub async fn latest_header(&self) -> anyhow::Result<Header> {
        Ok(self.melclient.latest_snapshot().await?.current_header())
    }

    pub async fn sync_wallet(&self) -> anyhow::Result<()> {
        let wallet_address = self.wwk.read().wallet.address;
        let latest_height = self
            .melclient
            .latest_snapshot()
            .await?
            .current_header()
            .height;

        if (latest_height.0 - self.wwk.read().wallet.height.0) < 100 {
            // we call `add_coins` unless we're too far out of sync with the network,
            // because downloading all the coins might take a while for wallets with lots of coins
            // and because we need to keep track of pending transactions.
            // For example, we don't want to:
            // 1. send a transaction (moves some coins into pending_outgoing)
            // 2. reset the wallet (clears pending_outgoing)
            // 3. immediately send another transaction that tries to use the same coins as the first transaction & fail

            let mut stream = self
                .melclient
                .stream_snapshots(self.wwk.read().wallet.height + BlockHeight(1))
                .take((latest_height.0 - self.wwk.read().wallet.height.0) as usize)
                .boxed();

            while let Some(snapshot) = stream.next().await {
                let mut new_coins = vec![];
                let mut spent_coins = vec![];

                let ccs = snapshot.get_coin_changes(wallet_address).await?;
                for cc in ccs {
                    match cc {
                        CoinChange::Add(id) => {
                            if let Some(data_height) = snapshot.get_coin(id).await? {
                                new_coins.push((id, data_height.coin_data));
                            }
                        }
                        CoinChange::Delete(id, _) => {
                            spent_coins.push(id);
                        }
                    }
                }

                // println!(
                //     "calling wallet.add_coins... wallet.height = {} | snapshot.height = {}",
                //     self.wwk.read().wallet.height.0,
                //     snapshot.current_header().height
                // );

                self.wwk.write().wallet.add_coins(
                    snapshot.current_header().height,
                    new_coins,
                    spent_coins,
                )?;
            }
        } else {
            // resync everything
            let latest_snapshot = self.melclient.latest_snapshot().await?;
            if let Some(owned_coins) = latest_snapshot.get_coins(wallet_address).await? {
                self.wwk
                    .write()
                    .wallet
                    .full_reset(latest_snapshot.current_header().height, owned_coins)?
            }
        }
        Ok(())
    }
}
