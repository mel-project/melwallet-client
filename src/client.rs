use anyhow::Context;
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
};

use http_types::{Body, Method, Request, Response, StatusCode, Url};
use smol::net::TcpStream;
use themelio_stf::{CoinData, CoinID, HexBytes, PoolKey, PoolState, Transaction, TxHash, TxKind};
use tmelcrypt::Ed25519SK;

use crate::{structs::WalletSummary, TransactionStatus, WalletDump};

/// A client to a particular wallet daemon.
#[derive(Clone, Debug)]
pub struct DaemonClient {
    endpoint: SocketAddr,
}

impl DaemonClient {
    /// Creates a new client.
    pub fn new(endpoint: SocketAddr) -> Self {
        Self { endpoint }
    }

    /// Lists all the wallets
    pub async fn list_wallets(&self) -> http_types::Result<BTreeMap<String, WalletSummary>> {
        successful(http_get(self.endpoint, "wallets").await?)
            .await?
            .body_json()
            .await
    }

    /// Create a wallet
    pub async fn dump_wallet(&self, name: &str) -> http_types::Result<Option<WalletDump>> {
        let mut resp = http_get(self.endpoint, &format!("wallets/{}", name)).await?;
        if resp.status() == StatusCode::NotFound {
            return Ok(None);
        }
        Ok(Some(resp.body_json().await?))
    }

    /// Gets a wallet
    pub async fn get_wallet(&self, name: &str) -> http_types::Result<Option<WalletClient>> {
        // needs to be dumpable
        if let Some(_dump) = self.dump_wallet(name).await? {
            Ok(Some(WalletClient {
                endpoint: self.endpoint,
                wallet_name: name.to_string(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Creates a wallet
    pub async fn create_wallet(
        &self,
        name: &str,
        testnet: bool,
        password: Option<String>,
    ) -> http_types::Result<()> {
        let mut adhoc_obj = BTreeMap::new();
        adhoc_obj.insert(
            "testnet".to_string(),
            serde_json::to_value(testnet).unwrap(),
        );
        if let Some(pwd) = password {
            adhoc_obj.insert("password".to_string(), serde_json::to_value(pwd).unwrap());
        }
        successful(
            http_with_body(
                self.endpoint,
                &format!("wallets/{}", name),
                Method::Put,
                serde_json::to_value(&adhoc_obj).unwrap(),
            )
            .await?,
        )
        .await?;
        Ok(())
    }

    /// Obtains pool info.
    pub async fn get_pool(&self, pool: PoolKey, testnet: bool) -> http_types::Result<PoolState> {
        Ok(successful(
            http_get(
                self.endpoint,
                &format!(
                    "pools/{}?{}",
                    pool.to_canonical()
                        .context("oh no")?
                        .to_string()
                        .replace("/", ":"),
                    if testnet { "testnet=1" } else { "" }
                ),
            )
            .await?,
        )
        .await?
        .body_json()
        .await?)
    }
}

/// An interface to a particular wallet.
#[derive(Clone, Debug)]
pub struct WalletClient {
    endpoint: SocketAddr,
    wallet_name: String,
}

async fn successful(mut resp: Response) -> http_types::Result<Response> {
    if resp.status() == StatusCode::Ok {
        Ok(resp)
    } else {
        return Err(anyhow::anyhow!(
            "non-200 response: ({}) {}",
            resp.status(),
            resp.body_string().await?
        )
        .into());
    }
}

impl WalletClient {
    /// Lock a wallet
    pub async fn lock(&self) -> http_types::Result<()> {
        successful(
            http_with_body(
                self.endpoint,
                &format!("wallets/{}/lock", self.wallet_name),
                Method::Post,
                vec![],
            )
            .await?,
        )
        .await?;
        Ok(())
    }

    /// Unlock a wallet
    pub async fn unlock(&self, password: Option<String>) -> http_types::Result<()> {
        let mut val = HashMap::new();
        val.insert("password", password);
        successful(
            http_with_body(
                self.endpoint,
                &format!("wallets/{}/unlock", self.wallet_name),
                Method::Post,
                serde_json::to_vec(&val)?,
            )
            .await?,
        )
        .await?;
        Ok(())
    }

    /// Send a 1000 MEL faucet transaction
    pub async fn send_faucet(&self) -> http_types::Result<TxHash> {
        let hash_string: String = successful(
            http_with_body(
                self.endpoint,
                &format!("wallets/{}/send-faucet", self.wallet_name),
                Method::Post,
                vec![],
            )
            .await?,
        )
        .await?
        .body_json()
        .await?;
        Ok(TxHash(hash_string.parse()?))
    }

    /// Send a transaction
    pub async fn send_tx(&self, tx: Transaction) -> http_types::Result<TxHash> {
        let hash_string: String = successful(
            http_with_body(
                self.endpoint,
                &format!("wallets/{}/send-tx", self.wallet_name),
                Method::Post,
                serde_json::to_value(tx)?,
            )
            .await?,
        )
        .await?
        .body_json()
        .await?;
        Ok(TxHash(hash_string.parse()?))
    }

    /// Obtain a prepared transaction
    pub async fn prepare_transaction(
        &self,
        kind: TxKind,
        desired_outputs: Vec<CoinData>,
        secret: Option<Ed25519SK>,
        data: Vec<u8>,
    ) -> http_types::Result<Transaction> {
        let mut adhoc = BTreeMap::new();
        adhoc.insert("kind".to_string(), serde_json::to_value(&kind)?);
        adhoc.insert(
            "outputs".to_string(),
            serde_json::to_value(&desired_outputs)?,
        );
        adhoc.insert("data".to_string(), serde_json::to_value(&HexBytes(data))?);
        if let Some(secret) = secret {
            adhoc.insert(
                "signing_key".to_string(),
                serde_json::to_value(hex::encode(&secret.0))?,
            );
        }
        successful(
            http_with_body(
                self.endpoint,
                &format!("wallets/{}/prepare-tx", self.wallet_name),
                Method::Post,
                serde_json::to_vec(&adhoc)?,
            )
            .await?,
        )
        .await?
        .body_json()
        .await
    }

    /// Check on a transaction, by transaction hash
    pub async fn get_transaction_status(
        &self,
        txhash: TxHash,
    ) -> http_types::Result<TransactionStatus> {
        Ok(successful(
            http_get(
                self.endpoint,
                &format!("wallets/{}/transactions/{}", self.wallet_name, txhash),
            )
            .await?,
        )
        .await?
        .body_json()
        .await?)
    }

    /// Adds a coin
    pub async fn add_coin(&self, coin_id: CoinID) -> http_types::Result<()> {
        successful(
            http_with_body(
                self.endpoint,
                &format!("wallets/{}/coins/{}", &self.wallet_name, coin_id),
                Method::Put,
                vec![],
            )
            .await?,
        )
        .await?;
        Ok(())
    }

    /// Obtains the current wallet summary.
    pub async fn summary(&self) -> http_types::Result<WalletSummary> {
        Ok(successful(
            http_get(
                self.endpoint,
                &format!("wallets/{}?summary=1", self.wallet_name),
            )
            .await?,
        )
        .await?
        .body_json()
        .await?)
    }
}

static AUTH_TOKEN: once_cell::sync::Lazy<Option<String>> =
    once_cell::sync::Lazy::new(|| std::env::var("MELWALLETD_AUTH_TOKEN").ok());

async fn http_get(endpoint: SocketAddr, path: &str) -> http_types::Result<Response> {
    let conn = TcpStream::connect(endpoint).await?;
    let mut req = Request::new(
        Method::Get,
        Url::parse(&format!("http://{}/{}", endpoint, path))?,
    );
    if let Some(token) = AUTH_TOKEN.as_ref() {
        req.insert_header("X-Melwalletd-Auth-Token", token);
    }
    Ok(async_h1::connect(conn, req).await?)
}

async fn http_with_body(
    endpoint: SocketAddr,
    path: &str,
    method: Method,
    body: impl Into<Body>,
) -> http_types::Result<Response> {
    let mut req = Request::new(
        method,
        Url::parse(&format!("http://{}/{}", endpoint, path))?,
    );
    req.set_body(body);
    if let Some(token) = AUTH_TOKEN.as_ref() {
        req.insert_header("X-Melwalletd-Auth-Token", token);
    }
    let conn = TcpStream::connect(endpoint).await?;
    Ok(async_h1::connect(conn, req).await?)
}
