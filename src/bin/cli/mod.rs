
use anyhow::Context;
use melwallet_client::{DaemonClient, WalletClient};

use clap::{Parser, crate_version};
use std::{net::SocketAddr, str::FromStr};
use themelio_stf::{ PoolKey};
use themelio_structs::{
    Address, CoinData, CoinID, CoinValue, Denom};
use tmelcrypt::{HashVal};




#[derive(Clone, Debug)]
pub struct CoinDataWrapper(pub CoinData);
impl FromStr for CoinDataWrapper {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let exploded = s.split(',').collect::<Vec<_>>();
        match exploded.as_slice() {
            [dest, amount] => {
                let dest: Address = dest.parse()?;
                let amount: CoinValue = amount.parse()?;
                Ok(CoinDataWrapper(CoinData {
                    covhash: dest,
                    value: amount,
                    denom: Denom::Mel,
                    additional_data: vec![],
                }))
            }
            [dest, amount, denom] => {
                let dest: Address = dest.parse()?;
                Ok(CoinDataWrapper(CoinData {
                    covhash: dest,
                    value: amount.parse()?,
                    denom: denom.parse()?,
                    additional_data: vec![],
                }))
            }
            &[dest, amount, denom, additional_data] => {
                let dest: Address = dest.parse()?;
                let additional_data: Vec<u8> = hex::decode(&additional_data)?;
                Ok(CoinDataWrapper(CoinData {
                    covhash: dest,
                    value: amount.parse()?,
                    denom: denom.parse()?,
                    additional_data,
                }))
            }
            _ => anyhow::bail!(
                "invalid destination specification (must be dest,amount[,denom[,additional_data]])"
            ),
        }
    }
}


#[derive(Parser, Clone, Debug)]
#[clap(
    version(crate_version!()),
    propagate_version(true)
)]
pub struct CommonArgs {
    #[clap(long, default_value = "127.0.0.1:11773")]
    /// HTTP endpoint of a running melwalletd instance
    pub endpoint: SocketAddr,
    // raw json instead of human readable
    #[clap(long)]
    pub raw: bool,
}

impl CommonArgs {
    pub fn dclient(&self) -> DaemonClient {
        DaemonClient::new(self.endpoint)
    }
}

#[derive(Parser, Clone, Debug)]
pub struct WalletArgs {
    #[clap(short)]
    /// Name of the wallet to create or use
    pub wallet: String,

    #[clap(flatten)]
    pub common: CommonArgs,
}

impl WalletArgs {
    pub async fn wallet(&self) -> http_types::Result<WalletClient> {
        Ok(self
            .common
            .dclient()
            .get_wallet(&self.wallet)
            .await?
            .context("no such wallet")?)
    }
}


#[derive(Parser, Clone, Debug)]
pub enum Args {
    /// Create a wallet
    Create {
        #[clap(flatten)]
        wargs: WalletArgs,
    },
    /// List all available wallets
    List(CommonArgs),
    /// Send a 1000 MEL faucet transaction for a testnet wallet
    SendFaucet(WalletArgs),
    /// Details of a wallet
    Summary(WalletArgs),
    /// Wait for a particular transaction to confirm
    WaitConfirmation {
        #[clap(flatten)]
        wargs: WalletArgs,
        txhash: HashVal,
    },
    /// Swaps money from one denomination to another
    Swap {
        #[clap(flatten)]
        wargs: WalletArgs,
        /// How much money to swap
        value: Option<CoinValue>,
        #[clap(long, short)]
        /// "From" denomination.
        from: Denom,
        #[clap(long, short)]
        /// "To" denomination.
        to: Denom,
        /// Whether or not to wait.
        #[clap(long)]
        wait: bool,
    },
    /// Supplies liquidity to Melswap
    LiqDeposit {
        #[clap(flatten)]
        wargs: WalletArgs,
        /// Number of the first denomination to deposit (in millionths)
        a_count: CoinValue,
        /// First denomination
        a_denom: Denom,
        /// Number of the second denomination to deposit (in millionths)
        b_count: CoinValue,
        /// Second denomination
        b_denom: Denom,
    },
    /// Automatically executes arbitrage trades on the core, "triangular" MEL/SYM/NOM-DOSC pairs
    Autoswap {
        #[clap(flatten)]
        wargs: WalletArgs,
        /// How much money to swap
        value: u128,
    },
    /// Stakes a certain number of syms.
    Stake {
        #[clap(flatten)]
        wargs: WalletArgs,
        /// How many microsyms to stake
        value: CoinValue,
        /// Ed25519 public key of the staker that receives voting rights
        staker_pubkey: String,
        /// When the stake takes effect. By default, as soon as possible.
        #[clap(long)]
        start: Option<u64>,
        /// How long will the stake last. By default, 1 epoch with 1 epoch waiting time.
        #[clap(long)]
        duration: Option<u64>,
    },
    /// Send a transaction to the network
    Send {
        #[clap(flatten)]
        wargs: WalletArgs,
        #[clap(long)]
        /// A string specifying who to send money to, in the format "dest,amount[,denom[,additional_data]]". For example, --to $ADDRESS,1 sends 1 µMEL to $ADDRESS. Can be specified multiple times to send money to multiple addresses.
        to: Vec<CoinDataWrapper>,
        /// Force the selection of a coin
        #[clap(long)]
        force_spend: Vec<CoinID>,
        /// Additional covenants. This often must be specified if we are spending coins that belong to other addresses, like covenant coins.
        #[clap(long)]
        add_covenant: Vec<String>,
        /// Dry run; dumps out the transaction to send as a hex string.
        #[clap(long)]
        dry_run: bool,
        /// "Ballast" to add to the fee; 50 is plenty for an extra ed25519 signature added manually later.
        #[clap(long, default_value = "0")]
        fee_ballast: usize,
    },
    /// Sends a raw transaction in hex, with no customization options.
    SendRaw {
        #[clap(flatten)]
        wargs: WalletArgs,
        txhex: String,
    },
    /// Unlocks a wallet. Will read password from stdin.
    Unlock {
        #[clap(flatten)]
        wargs: WalletArgs,
    },
    /// Exports the secret key of a wallet. Will read password from stdin.
    ExportSk {
        #[clap(flatten)]
        wargs: WalletArgs,
    },
    /// Locks a wallet down again.
    Lock {
        #[clap(flatten)]
        wargs: WalletArgs,
    },
    /// Checks a pool.
    Pool {
        #[clap(flatten)]
        common: CommonArgs,
        #[clap(long)]

        /// What pool to check, in slash-separated tickers (for example, MEL/SYM or MEL/N-DOSC).
        pool: PoolKey,
    },
    /// Provide a secret key to import an existing wallet
    Import {
        #[clap(flatten)]
        wargs: WalletArgs,

        #[clap(long, short)]
        /// The secret key of the wallet used to import
        secret: String,
    },

    /// Show the summary of the network connected to the associated melwalletd instance
    NetworkSummary(CommonArgs),
    
    /// Generate bash autocompletions
    GenerateAutocomplete,
}

