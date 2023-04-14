use anyhow::Context;

use clap::Parser;
use melstructs::{Address, CoinData, CoinID, CoinValue, Denom, NetID, PoolKey};
use std::str::FromStr;
use tmelcrypt::HashVal;

#[derive(Parser, Clone, Debug)]
/// Mel Wallet Command Line Interface
pub struct Args {
    #[clap(long)]
    // path to the wallet to create or use
    pub wallet_path: String,
    #[clap(subcommand)]
    pub subcommand: SubcommandArgs,
}

#[derive(Parser, Clone, Debug)]
pub enum SubcommandArgs {
    /// Create a wallet.  Ex: `melwallet-cli --wallet-path wallet123 create`
    Create {
        #[clap(long)]
        network: NetID,
    },
    /// Send a 1000 MEL faucet transaction for a testnet wallet
    SendFaucet {
        /// Whether or not to wait for the the transaction to confirm
        #[clap(long)]
        wait: bool,
    },
    /// Details of a wallet
    Summary,

    /// Send a transaction to the network
    Send {
        /// FORMAT: `destination,amount[,denom[,additional_data]]`
        /// Specifies where to send funds; denom and additional_data are optional.
        /// For example, `--to $ADDRESS,100.0` sends 100 MEL to $ADDRESS.
        /// Amounts must be specified with numbers on either side of the decimal. Ex: 10.0, 0.1
        /// Can be specified multiple times to send money to multiple addresses.
        /// `denom` defaults to MEL
        /// `additional_data` must be hex encoded by default, but allows passsing ascii with `ascii=""`
        ///
        #[clap(long, verbatim_doc_comment)]
        to: Vec<CoinDataWrapper>,

        /// Force the selection of a coin
        #[clap(long)]
        force_spend: Vec<CoinID>,
        /// Additional covenants. This often must be specified if we are spending coins that belong to other addresses, like covenant coins.
        #[clap(long)]
        add_covenant: Vec<String>,
        /// The contents of the data field, in hexadecimal.
        #[clap(long, default_value = "")]
        hex_data: String,
        /// Dumps the transaction as a hex string.
        #[clap(long)]
        dry_run: bool,
        /// Whether or not to wait for the the transaction to confirm
        #[clap(long)]
        wait: bool,
        /// "Ballast" to add to the fee; 50 is plenty for an extra ed25519 signature added manually later.
        #[clap(long, default_value = "0")]
        fee_ballast: usize,
    },
    /// Checks a pool.
    #[clap[verbatim_doc_comment]]
    Pool {
        /// What pool to check, in slash-separated tickers (for example, MEL/SYM or MEL/ERG).
        pool: PoolKey,
    },
    /// Swaps money from one denomination to another
    Swap {
        /// How much money to swap
        #[clap(long, short)]
        value: CoinValue,
        #[clap(long, short)]
        /// "From" denomination.
        from: Denom,
        #[clap(long, short)]
        /// "To" denomination.
        to: Denom,
        /// Whether or not to wait for the the transaction to confirm
        #[clap(long)]
        wait: bool,
    },
    /// Supplies liquidity to Melswap
    LiqDeposit {
        /// Number of the first denomination to deposit (in millionths)
        a_count: CoinValue,
        /// First denomination
        a_denom: Denom,
        /// Number of the second denomination to deposit (in millionths)
        b_count: CoinValue,
        /// Second denomination
        b_denom: Denom,
        /// Whether or not to wait for the the transaction to confirm
        #[clap(long)]
        wait: bool,
    },
    /// Wait for a particular transaction to confirm
    WaitConfirmation {
        txhash: HashVal,
    },
    /// Sends a raw transaction in hex, with no customization options.
    SendRaw {
        txhex: String,
        /// Whether or not to wait for the the transaction to confirm
        #[clap(long)]
        wait: bool,
    },
    /// Exports the secret key of a wallet. Will read password from stdin.
    ExportSk,
    /// Provide a secret key to import an existing wallet
    #[clap[verbatim_doc_comment]]
    ImportSk {
        #[clap(long, short)]
        /// The secret key of the wallet used to import
        secret: String,

        #[clap(long, short)]
        network: NetID,
    },

    /// Automatically executes arbitrage trades on the core, "triangular" MEL/SYM/ERG pairs
    Autoswap {
        /// How much MEL to swap
        value: CoinValue,
    },
    /// Stakes a certain number of syms
    #[clap[ verbatim_doc_comment]]
    Stake {
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
        /// Whether or not to wait for the the transaction to confirm
        #[clap(long)]
        wait: bool,
    },
    // /// Shows the summary of the network for the wallet
    NetworkSummary,
    /// Generate bash autocompletions
    #[clap[verbatim_doc_comment]]
    GenerateAutocomplete,
}

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
                    additional_data: vec![].into(),
                }))
            }
            [dest, amount, denom] => {
                let dest: Address = dest.parse()?;
                Ok(CoinDataWrapper(CoinData {
                    covhash: dest,
                    value: amount.parse()?,
                    denom: denom.parse()?,
                    additional_data: vec![].into(),
                }))
            }
            &[dest, amount, denom, additional_data] => {
                let dest: Address = dest.parse()?;

                let additional_data = {
                    if !additional_data.contains('=') {
                        anyhow::Ok(hex::decode(additional_data)?)
                    } else {
                        let (data_type, content) = additional_data.split_once('=').context(
                            "Unable to parse additional_data, acceptable fields: ascii=",
                        )?;

                        if data_type == "ascii" {
                            anyhow::Ok(content.as_bytes().into())
                        } else {
                            Err(anyhow::anyhow!(
                                "Unable to parse additional_data, acceptable fields: ascii="
                            ))
                        }
                    }
                }?;
                Ok(CoinDataWrapper(CoinData {
                    covhash: dest,
                    value: amount.parse()?,
                    denom: denom.parse()?,
                    additional_data: additional_data.into(),
                }))
            }
            _ => anyhow::bail!(
                "invalid destination specification (must be dest,amount[,denom[,additional_data]])"
            ),
        }
    }
}
