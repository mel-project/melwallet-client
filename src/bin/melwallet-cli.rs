use anyhow::Context;
use autoswap::do_autoswap;
use colored::Colorize;
use melwallet_client::{DaemonClient, WalletClient, WalletSummary};
use smol::{prelude::*, process::Child};
use std::{io::Write, time::Duration};
use std::{net::SocketAddr, str::FromStr};
use structopt::StructOpt;
use tabwriter::TabWriter;
use themelio_stf::{melvm::Covenant, PoolKey};
use themelio_structs::{
    Address, CoinData, CoinID, CoinValue, Denom, NetID, StakeDoc, Transaction, TxHash, TxKind,
    STAKE_EPOCH,
};
use tmelcrypt::{Ed25519PK, HashVal};
mod autoswap;

#[derive(StructOpt, Clone, Debug)]
enum Args {
    /// Create a wallet
    Create {
        #[structopt(flatten)]
        wargs: WalletArgs,
        #[structopt(long)]
        testnet: bool,
    },
    /// List all available wallets
    List(CommonArgs),
    /// Send a 1000 MEL faucet transaction for a testnet wallet
    SendFaucet(WalletArgs),
    /// Details of a wallet
    Summary(WalletArgs),
    /// Wait for a particular transaction to confirm
    WaitConfirmation {
        #[structopt(flatten)]
        wargs: WalletArgs,
        txhash: HashVal,
    },
    /// Swaps money from one denomination to another
    Swap {
        #[structopt(flatten)]
        wargs: WalletArgs,
        /// How much money to swap
        value: Option<u128>,
        #[structopt(long, short)]
        /// "From" denomination.
        from: Denom,
        #[structopt(long, short)]
        /// "To" denomination.
        to: Denom,
        /// Whether or not to wait.
        #[structopt(long)]
        wait: bool,
    },
    /// Supplies liquidity to Melswap
    LiqDeposit {
        #[structopt(flatten)]
        wargs: WalletArgs,
        /// Number of the first denomination to deposit (in millionths)
        a_count: u128,
        /// First denomination
        a_denom: Denom,
        /// Number of the second denomination to deposit (in millionths)
        b_count: u128,
        /// Second denomination
        b_denom: Denom,
    },
    /// Automatically executes arbitrage trades on the core, "triangular" MEL/SYM/NOM-DOSC pairs
    Autoswap {
        #[structopt(flatten)]
        wargs: WalletArgs,
        /// How much money to swap
        value: u128,
    },
    /// Stakes a certain number of syms.
    Stake {
        #[structopt(flatten)]
        wargs: WalletArgs,
        /// How many microsyms to stake
        value: u128,
        /// Ed25519 public key of the staker that receives voting rights
        staker_pubkey: String,
        /// When the stake takes effect. By default, as soon as possible.
        #[structopt(long)]
        start: Option<u64>,
        /// How long will the stake last. By default, 1 epoch with 1 epoch waiting time.
        #[structopt(long)]
        duration: Option<u64>,
    },
    /// Send a transaction to the network
    Send {
        #[structopt(flatten)]
        wargs: WalletArgs,
        #[structopt(long)]
        /// A string specifying who to send money to, in the format "dest,amount[,denom[,additional_data]]". For example, --to $ADDRESS,1 sends 1 µMEL to $ADDRESS. Can be specified multiple times to send money to multiple addresses.
        to: Vec<CoinDataWrapper>,
        /// Force the selection of a coin
        #[structopt(long)]
        force_spend: Vec<CoinID>,
        /// Additional covenants. This often must be specified if we are spending coins that belong to other addresses, like covenant coins.
        #[structopt(long)]
        add_covenant: Vec<String>,
    },
    /// Unlocks a wallet. Will read password from stdin.
    Unlock {
        #[structopt(flatten)]
        wargs: WalletArgs,
    },
    /// Exports the secret key of a wallet. Will read password from stdin.
    ExportSk {
        #[structopt(flatten)]
        wargs: WalletArgs,
    },
    /// Locks a wallet down again.
    Lock {
        #[structopt(flatten)]
        wargs: WalletArgs,
    },
    /// Checks a pool.
    Pool {
        #[structopt(flatten)]
        common: CommonArgs,
        #[structopt(long)]
        /// Whether or not to use the testnet.
        testnet: bool,

        /// What pool to check, in slash-separated tickers (for example, MEL/SYM or MEL/N-DOSC).
        pool: PoolKey,
    },
    Import {
        #[structopt(flatten)]
        wargs: WalletArgs,

        #[structopt(long)]
        /// Whether or not to use the testnet.
        testnet: bool,

        #[structopt(long, short)]
        /// The secret key of the wallet used to import
        secret: String,
    },
}

#[derive(Clone, Debug)]
struct CoinDataWrapper(CoinData);

impl FromStr for CoinDataWrapper {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let exploded = s.split(',').collect::<Vec<_>>();
        match exploded.as_slice() {
            [dest, amount] => {
                let dest: Address = dest.parse()?;
                let amount: u128 = amount.parse()?;
                Ok(CoinDataWrapper(CoinData {
                    covhash: dest,
                    value: amount.into(),
                    denom: Denom::Mel,
                    additional_data: vec![],
                }))
            }
            [dest, amount, denom] => {
                let dest: Address = dest.parse()?;
                let amount: u128 = amount.parse()?;
                Ok(CoinDataWrapper(CoinData {
                    covhash: dest,
                    value: amount.into(),
                    denom: denom.parse()?,
                    additional_data: vec![],
                }))
            }
            &[dest, amount, denom, additional_data] => {
                let dest: Address = dest.parse()?;
                let amount: u128 = amount.parse()?;
                let additional_data: Vec<u8> = hex::decode(&additional_data)?;
                Ok(CoinDataWrapper(CoinData {
                    covhash: dest,
                    value: amount.into(),
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

#[derive(StructOpt, Clone, Debug)]
struct WalletArgs {
    #[structopt(short)]
    /// Name of the wallet to create or use
    wallet: String,

    #[structopt(flatten)]
    common: CommonArgs,
}

impl WalletArgs {
    async fn wallet(&self) -> http_types::Result<WalletClient> {
        Ok(self
            .common
            .dclient()
            .get_wallet(&self.wallet)
            .await?
            .context("no such wallet")?)
    }
}

#[derive(StructOpt, Clone, Debug)]
struct CommonArgs {
    #[structopt(long, default_value = "127.0.0.1:11773")]
    /// HTTP endpoint of a running melwalletd instance
    endpoint: SocketAddr,
}

impl CommonArgs {
    fn dclient(&self) -> DaemonClient {
        DaemonClient::new(self.endpoint)
    }
}

struct KillOnDrop(Option<Child>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
        }
    }
}

async fn wait_tx(wallet: &WalletClient, txhash: TxHash) -> http_types::Result<()> {
    loop {
        let status = wallet.get_transaction_status(txhash).await?;
        if let Some(height) = status.confirmed_height {
            eprintln!("Confirmed at height {}", height);
            eprintln!(
                "(in block explorer: https://{}/blocks/{}/{})",
                if wallet.summary().await?.network == NetID::Testnet {
                    "scan-testnet.themelio.org"
                } else {
                    "scan.themelio.org"
                },
                height,
                txhash
            );
            break;
        } else {
            eprint!("{}", ".".yellow());
            smol::Timer::after(Duration::from_secs(1)).await;
        }
    }
    Ok(())
}

fn main() -> http_types::Result<()> {
    smolscale::block_on(async move {
        let mut stdin = smol::io::BufReader::new(smol::Unblock::new(std::io::stdin()));
        let mut twriter = TabWriter::new(std::io::stderr());
        let args = Args::from_args();
        match args {
            Args::Create { wargs, testnet } => {
                let dclient = wargs.common.dclient();
                eprint!("Enter password: ");
                let mut pwd = "".to_string();
                stdin.read_line(&mut pwd).await?;
                pwd.truncate(pwd.len() - 1);
                dclient
                    .create_wallet(&wargs.wallet, testnet, Some(pwd), None)
                    .await?;
                let summary = dclient
                    .list_wallets()
                    .await?
                    .get(&wargs.wallet)
                    .cloned()
                    .context("just-created wallet is now gone")?;
                write_wallet_summary(&mut twriter, &wargs.wallet, &summary)?;
                writeln!(twriter)?;
                twriter.flush()?;
            }
            Args::Import { 
                wargs,
                testnet,
                secret
             } => {
                let dclient = wargs.common.dclient();
                eprint!("Enter password: ");
                let mut pwd = "".to_string();
                stdin.read_line(&mut pwd).await?;
                pwd.truncate(pwd.len() - 1);
                dclient
                    .create_wallet(&wargs.wallet, testnet, Some(pwd), Some(secret))
                    .await?;
                let summary = dclient
                    .list_wallets()
                    .await?
                    .get(&wargs.wallet)
                    .cloned()
                    .context("just-created wallet is now gone")?;

                write_wallet_summary(&mut twriter, &wargs.wallet, &summary)?;
                writeln!(twriter)?;
                twriter.flush()?;
             }
            Args::List(common) => {
                let dclient = common.dclient();
                let wallets = dclient.list_wallets().await?;
                for (name, summary) in wallets {
                    write_wallet_summary(&mut twriter, &name, &summary)?;
                    writeln!(twriter)?;
                }
            }
            Args::Summary(wallet) => {
                let summary = wallet.wallet().await?.summary().await?;
                write_wallet_summary(&mut twriter, &wallet.wallet, &summary)?;
            }
            Args::SendFaucet(wallet) => {
                let txhash = wallet.wallet().await?.send_faucet().await?;
                write_txhash(&mut twriter, &wallet.wallet, txhash)?;
            }
            Args::Send {
                wargs,
                to,
                force_spend,
                add_covenant,
            } => {
                let wallet = wargs.wallet().await?;
                let desired_outputs = to.iter().map(|v| v.0.clone()).collect::<Vec<_>>();
                let tx = wallet
                    .prepare_transaction(
                        TxKind::Normal,
                        force_spend,
                        desired_outputs,
                        add_covenant
                            .into_iter()
                            .map(|s| Ok(Covenant(hex::decode(&s)?)))
                            .collect::<anyhow::Result<Vec<_>>>()?,
                        vec![],
                        vec![],
                    )
                    .await?;
                send_tx(&mut twriter, stdin, wallet, tx).await?
            }
            Args::Stake {
                wargs,
                value,
                start,
                duration,
                staker_pubkey,
            } => {
                let staker_pubkey = Ed25519PK::from_bytes(
                    &hex::decode(&staker_pubkey).context("staker pubkey must be hex")?,
                )
                .context("staker pubkey must be 32 bytes")?;
                let wallet = wargs.wallet().await?;
                let last_header = wargs
                    .common
                    .dclient()
                    .get_summary(wallet.summary().await?.network == NetID::Testnet)
                    .await?;
                let next_epoch = last_header.height.epoch() + 1;
                let start_epoch = start.unwrap_or_default().max(next_epoch);
                let duration = duration.unwrap_or(1);
                let end_epoch = start_epoch + duration;
                let post_end_epoch = start_epoch + duration + 1;
                const BLOCKS_IN_DAY: u64 = 2880;
                writeln!(
                    twriter,
                    "Latest:\tblock {} (epoch {})",
                    (last_header.height).to_string().bold(),
                    last_header.height / STAKE_EPOCH
                )?;
                writeln!(
                    twriter,
                    "Voting rights start:\tblock {} (epoch {}, in {} days)",
                    (start_epoch * STAKE_EPOCH).to_string().bold().bright_blue(),
                    start_epoch,
                    (start_epoch * STAKE_EPOCH - last_header.height.0) / BLOCKS_IN_DAY
                )?;
                writeln!(
                    twriter,
                    "Voting rights end:\tblock {} (epoch {}, in {} days)",
                    (end_epoch * STAKE_EPOCH).to_string().bold().bright_yellow(),
                    end_epoch,
                    (end_epoch * STAKE_EPOCH - last_header.height.0) / BLOCKS_IN_DAY
                )?;
                writeln!(
                    twriter,
                    "Syms unlock:\tblock {} (epoch {}, in {} days)",
                    (post_end_epoch * STAKE_EPOCH)
                        .to_string()
                        .bold()
                        .bright_green(),
                    post_end_epoch,
                    (post_end_epoch * STAKE_EPOCH - last_header.height.0) / BLOCKS_IN_DAY
                )?;
                writeln!(
                    twriter,
                    "{}",
                    "WARNING: Syms are immediately locked no matter when voting rights start!"
                        .bright_red()
                        .bold()
                        .italic()
                )?;
                let tx = wallet
                    .prepare_stake_transaction(StakeDoc {
                        e_start: start_epoch,
                        e_post_end: post_end_epoch,
                        syms_staked: value.into(),
                        pubkey: staker_pubkey,
                    })
                    .await?;
                send_tx(&mut twriter, stdin, wallet, tx).await?
            }
            Args::WaitConfirmation { wargs, txhash } => {
                wait_tx(&wargs.wallet().await?, TxHash(txhash)).await?
            }
            Args::Unlock { wargs } => {
                let wallet = wargs.wallet().await?;
                eprint!("Enter password: ");
                let mut pwd = "".to_string();
                stdin.read_line(&mut pwd).await?;
                pwd.truncate(pwd.len() - 1);
                wallet.unlock(Some(pwd)).await?;
            }
            Args::ExportSk { wargs } => {
                let wallet = wargs.wallet().await?;
                eprint!("Enter password: ");
                let mut pwd = "".to_string();
                stdin.read_line(&mut pwd).await?;
                pwd.truncate(pwd.len() - 1);
                let sk = wallet.export_sk(Some(pwd)).await?;
                writeln!(twriter, "{}", sk.bold().bright_blue(),)?;
            }
            Args::Lock { wargs } => {
                let wallet = wargs.wallet().await?;
                wallet.lock().await?;
            }
            Args::Pool {
                common,
                pool,
                testnet,
            } => {
                let pool = pool.to_canonical().context("cannot canonicalize")?;
                let client = common.dclient();
                let pool_state = client.get_pool(pool, testnet).await?;
                let ratio = pool_state.lefts as f64 / pool_state.rights as f64;
                writeln!(
                    twriter,
                    "{} {}\t= {} {}",
                    "1".bold().bright_green(),
                    pool.left.to_string().italic(),
                    format!("{}", 1.0 / ratio).bold().yellow(),
                    pool.right.to_string().italic()
                )?;
                writeln!(
                    twriter,
                    "{} {}\t= {} {}",
                    "1".bold().yellow(),
                    pool.right.to_string().italic(),
                    format!("{}", ratio).bold().bright_green(),
                    pool.left.to_string().italic()
                )?;
            }
            Args::Autoswap { wargs, value } => {
                let daemon = wargs.common.dclient();
                let wallet = wargs.wallet().await?;
                do_autoswap(daemon, wallet, value.into()).await;
            }
            Args::Swap {
                wargs,
                value,
                from,
                to,
                wait,
            } => {
                let wallet = wargs.wallet().await?;
                let max_value =
                    wallet.summary().await?.detailed_balance[&hex::encode(from.to_bytes())];
                let max_value = if from == Denom::Mel {
                    max_value / 2
                } else {
                    max_value
                };
                let value = value.unwrap_or_else(|| max_value.into());
                let pool_key = PoolKey::new(from, to);
                let to_send = wallet
                    .prepare_transaction(
                        TxKind::Swap,
                        vec![],
                        vec![CoinData {
                            value: value.into(),
                            denom: from,
                            additional_data: vec![],
                            covhash: wallet.summary().await?.address,
                        }],
                        vec![],
                        pool_key.to_bytes(),
                        vec![],
                    )
                    .await?;
                writeln!(twriter, "{}", "SWAPPING".bold())?;
                writeln!(
                    twriter,
                    "From:\t{} {}",
                    CoinValue(value).to_string().bold().bright_green(),
                    from
                )?;
                let pool_state = wargs
                    .common
                    .dclient()
                    .get_pool(pool_key, wallet.summary().await?.network == NetID::Testnet)
                    .await?;
                let to_value = if from == pool_key.right {
                    pool_state.clone().swap_many(0, value).0
                } else {
                    pool_state.clone().swap_many(value, 0).1
                };
                writeln!(
                    twriter,
                    "To:\t{} {} (approximate)",
                    CoinValue(to_value).to_string().bold().yellow(),
                    to
                )?;
                twriter.flush()?;
                proceed_prompt(&mut stdin).await?;
                let txhash = wallet.send_tx(to_send).await?;
                write_txhash(&mut twriter, &wargs.wallet, txhash)?;
                if wait {
                    wait_tx(&wallet, txhash).await?
                }
            }
            Args::LiqDeposit {
                wargs,
                a_count,
                a_denom,
                b_count,
                b_denom,
            } => {
                let wallet = wargs.wallet().await?;
                let covhash = wallet.summary().await?.address;
                let poolkey = PoolKey::new(a_denom, b_denom);
                let left_denom = poolkey.left;
                let right_denom = poolkey.right;
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
                let tx = wallet
                    .prepare_transaction(
                        TxKind::LiqDeposit,
                        vec![],
                        vec![
                            CoinData {
                                value: left_count.into(),
                                denom: left_denom,
                                covhash,
                                additional_data: vec![],
                            },
                            CoinData {
                                value: right_count.into(),
                                denom: right_denom,
                                covhash,
                                additional_data: vec![],
                            },
                        ],
                        vec![],
                        poolkey.to_bytes(),
                        vec![],
                    )
                    .await?;
                send_tx(&mut twriter, stdin, wallet, tx).await?;
            }
        }
        twriter.flush()?;
        Ok(())
    })
}

async fn send_tx(
    mut twriter: impl Write,
    mut stdin: impl AsyncRead + Unpin,
    wallet: WalletClient,
    tx: Transaction,
) -> anyhow::Result<()> {
    writeln!(twriter, "{}", "TRANSACTION RECIPIENTS".bold())?;
    writeln!(twriter, "{}", "Address\tAmount\tAdditional data".italic())?;
    for output in tx.outputs.iter() {
        writeln!(
            twriter,
            "{}\t{} {}\t{:?}",
            output.covhash.to_string().bright_blue(),
            output.value,
            match output.denom {
                Denom::Mel => "MEL",
                Denom::Sym => "SYM",
                Denom::Erg => "ERG",
                Denom::Custom(_) => "(custom token)",
                Denom::NewCoin => "(new token type)",
            },
            hex::encode(&output.additional_data)
        )?;
    }
    writeln!(twriter, "{}\t{} MEL", " (network fees)".yellow(), tx.fee)?;
    twriter.flush()?;
    proceed_prompt(&mut stdin).await?;
    let txhash = wallet.send_tx(tx).await?;
    write_txhash(&mut twriter, wallet.name(), txhash)?;
    Ok(())
}

fn write_wallet_summary(
    out: &mut impl Write,
    wallet_name: &str,
    summary: &WalletSummary,
) -> anyhow::Result<()> {
    writeln!(
        out,
        "Wallet name:\t{} {}",
        wallet_name.bold(),
        if summary.locked {
            "(locked)".red()
        } else {
            "(unlocked)".green()
        }
    )?;
    writeln!(
        out,
        "Network:\t{}",
        match summary.network {
            NetID::Mainnet => "mainnet".bright_green().bold(),
            NetID::Testnet => "testnet".yellow().bold(),
            NetID::Custom02 => todo!(),
            NetID::Custom03 => todo!(),
            NetID::Custom04 => todo!(),
            NetID::Custom05 => todo!(),
            NetID::Custom06 => todo!(),
            NetID::Custom07 => todo!(),
            NetID::Custom08 => todo!(),
        }
    )?;
    writeln!(
        out,
        "Address:\t{}",
        summary.address.to_string().bright_blue()
    )?;
    writeln!(
        out,
        "Balance:\t{}",
        format!("{}\tMEL", summary.total_micromel)
    )?;
    for (k, v) in summary.detailed_balance.iter() {
        let denom = match k.as_str() {
            "6d" => continue,
            "73" => "SYM",
            "64" => "ERG",
            v => v,
        };
        writeln!(out, "\t{}\t{}", v, denom)?;
    }
    writeln!(
        out,
        "Staked:\t{}",
        format!("{}\tSYM", summary.staked_microsym)
    )?;
    Ok(())
}

fn write_txhash(out: &mut impl Write, wallet_name: &str, txhash: TxHash) -> anyhow::Result<()> {
    writeln!(out, "Transaction hash:\t{}", txhash.to_string().bold())?;
    writeln!(
        out,
        "(wait for confirmation with {})",
        format!(
            "melwallet-cli wait-confirmation -w {} {}",
            wallet_name, txhash
        )
        .bright_blue(),
    )?;
    Ok(())
}

async fn proceed_prompt(stdin: &mut (impl AsyncRead + Unpin)) -> anyhow::Result<()> {
    eprintln!("Proceed? [y/N] ");
    let mut letter = [0u8; 1];
    while letter[0].is_ascii_whitespace() || letter[0] == 0 {
        stdin.read_exact(&mut letter).await?;
    }
    if letter[0] != 0x79 {
        anyhow::bail!("canceled");
    }
    Ok(())
}
