use melwallet::Wallet;
use serde::{Deserialize, Serialize};
use tmelcrypt::Ed25519SK;

#[derive(Serialize, Deserialize)]
pub struct WalletWithKey {
    pub wallet: Wallet,
    pub secret_key: Ed25519SK,
}
