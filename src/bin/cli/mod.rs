
use anyhow::{Context};
use melwallet_client::{DaemonClient, WalletClient};

use clap::{Parser, crate_version};
use terminal_size::{Width, terminal_size};
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


                let additional_data = {
                    if !additional_data.contains('=') {
                        anyhow::Ok(hex::decode(&additional_data)?)
                    
                    }
                    else{
                        let (data_type, content) = additional_data.split_once('=')
                        .context("Unable to parse additional_data, acceptable fields: ascii=")?;

                        if data_type == "ascii" {
                            anyhow::Ok(content.as_bytes().into())
                        }
                        else {
                            Err(anyhow::anyhow!("Unable to parse additional_data, acceptable fields: ascii="))
                        }
                    }

                }?;
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
    #[clap(display_order(995),long, default_value = "127.0.0.1:11773")]
    /// HTTP endpoint of a running melwalletd instance
    pub endpoint: SocketAddr,
    /// Outputs raw, unformatted json
    #[clap(display_order(995),long)]
    pub raw: bool,
}

impl CommonArgs {
    pub fn dclient(&self) -> DaemonClient {
        let a = DaemonClient::new(self.endpoint);
        a
    }
}

#[derive(Parser, Clone, Debug)]
pub struct WalletArgs {
    #[clap(display_order(0), short, long)]
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
        .context(format!("Could not find wallet with name: {}",&self.wallet))?)
    }
    
}


#[derive(Parser, Clone, Debug)]
#[clap(
    max_term_width(400),
    term_width(
        if let Some((Width(w), _)) = terminal_size(){
            w as usize
        }
        else{120}
    ),
    version(crate_version!()),
    propagate_version(true),
    
)]
/// Themelio Commandline Wallet

pub enum Args {
    /// Create a wallet.  Ex: `melwallet-cli create -w wallet123`
    #[clap[display_order(1)]]
    Create {
        #[clap(flatten)]
        wargs: WalletArgs,
    },
    /// List all available wallets
    #[clap[display_order(1)]]
    List(CommonArgs),
    /// Unlocks a wallet. Ex: `melwallet-cli unlock -w wallet123`
    #[clap[display_order(3)]]
    Unlock {
        #[clap(flatten)]
        wargs: WalletArgs,
    },
    /// Send a 1000 MEL faucet transaction for a testnet wallet
    #[clap[display_order(4)]]
    SendFaucet(WalletArgs),
    /// Details of a wallet
    #[clap[display_order(5)]]
    Summary(WalletArgs),
    /// Locks a wallet 
    #[clap[display_order(6)]]
    Lock {
        #[clap(flatten)]
        wargs: WalletArgs,
    },
    /// Send a transaction to the network
    #[clap[display_order(8)]]
    Send {
        #[clap(flatten)]
        wargs: WalletArgs,
        /// FORMAT: "destination,amount[,denom[,additional_data]]"
        /// Specifies where to send funds; denom and additional_data are optional.
        /// For example, "--to $ADDRESS,100.0" sends 100 MEL to $ADDRESS. 
        /// Amounts must be specified with numbers on either side of the decimal. Ex: 10.0, 0.1
        /// Can be specified multiple times to send money to multiple addresses.
        /// ‎
        #[clap(display_order(1),long, verbatim_doc_comment)]
        to: Vec<CoinDataWrapper>,
        /// Force the selection of a coin
        #[clap(display_order(990),long)]
        force_spend: Vec<CoinID>,
        /// Additional covenants. This often must be specified if we are spending coins that belong to other addresses, like covenant coins.
        #[clap(display_order(990),long)]
        add_covenant: Vec<String>,
        /// Dumps the transaction as a hex string.
        #[clap(display_order(990),long)]
        dry_run: bool,
        /// "Ballast" to add to the fee; 50 is plenty for an extra ed25519 signature added manually later.
        #[clap(display_order(990),long, default_value = "0")]
        fee_ballast: usize,
    },
    /// Wait for a particular transaction to confirm
    #[clap[display_order(8)]]
    WaitConfirmation {
        #[clap(flatten)]
        wargs: WalletArgs,
        txhash: HashVal,
    },
    /// Sends a raw transaction in hex, with no customization options.
    #[clap[display_order(9)]]
    SendRaw {
        #[clap(flatten)]
        wargs: WalletArgs,
        txhex: String,
    },
    /// Exports the secret key of a wallet. Will read password from stdin.
    #[clap[display_order(10)]]
    ExportSk {
        #[clap(flatten)]
        wargs: WalletArgs,
    },
    /// Provide a secret key to import an existing wallet
    /// ‎
    #[clap[display_order(11),verbatim_doc_comment]]
    Import {
        #[clap(flatten)]
        wargs: WalletArgs,

        #[clap(long, short)]
        /// The secret key of the wallet used to import
        secret: String,
    },

    /// Checks a pool. 
    #[clap[display_order(12),verbatim_doc_comment]]
    Pool {
        #[clap(flatten)]
        common: CommonArgs,
        #[clap(long)]

        /// What pool to check, in slash-separated tickers (for example, MEL/SYM or MEL/ERG).
        pool: PoolKey,
    },
    /// Swaps money from one denomination to another
    #[clap[display_order(13)]]
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
    #[clap[display_order(21)]]
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
    /// Automatically executes arbitrage trades on the core, "triangular" MEL/SYM/ERG pairs
    #[clap[display_order(22)]]
    Autoswap {
        #[clap(flatten)]
        wargs: WalletArgs,
        /// How much money to swap
        value: u128,
    },
    /// Stakes a certain number of syms
    /// ‎
    #[clap[display_order(23), verbatim_doc_comment]]
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
    /// Show the summary of the network connected to the associated melwalletd instance
    #[clap[display_order(24)]]
    NetworkSummary(CommonArgs),

    
    /// Generate bash autocompletions
    #[clap[display_order(998), verbatim_doc_comment]]
    GenerateAutocomplete,
}

