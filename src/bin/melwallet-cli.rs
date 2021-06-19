use anyhow::Context;
use colored::Colorize;
use melwallet_client::{DaemonClient, WalletClient, WalletSummary};
use smol::{prelude::*, process::Child};
use std::{convert::TryInto, io::Write, time::Duration};
use std::{net::SocketAddr, str::FromStr};
use structopt::StructOpt;
use tabwriter::TabWriter;
use themelio_stf::{melvm::CovHash, CoinData, CoinID, Denom, NetID, TxHash};
use tmelcrypt::{Ed25519SK, HashVal};

#[derive(StructOpt, Clone, Debug)]
enum Args {
    /// Create a wallet
    Create {
        #[structopt(flatten)]
        wargs: WalletArgs,
        #[structopt(long)]
        testnet: bool,
    },
    /// Add a coin to a wallet
    AddCoin {
        #[structopt(flatten)]
        wargs: WalletArgs,
        coin: CoinID,
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
    /// Send a transaction to the network
    SendTx {
        #[structopt(flatten)]
        wargs: WalletArgs,
        #[structopt(long)]
        /// A string specifying who to send money to, in the format "dest,amount[,denom[,additional_data]]". For example, --to $ADDRESS,1 sends 1 µMEL to $ADDRESS. Can be specified multiple times to send money to multiple addresses.
        to: Vec<CoinDataWrapper>,
        #[structopt(long)]
        /// Hexadecimal secret key. Optional if the wallet is unlocked.
        secret: Option<String>,
    },
    /// Unlocks a wallet. Will read password from stdin.
    Unlock {
        #[structopt(flatten)]
        wargs: WalletArgs,
    },
    /// Locks a wallet down again.
    Lock {
        #[structopt(flatten)]
        wargs: WalletArgs,
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
                let dest: CovHash = dest.parse()?;
                let amount: u128 = amount.parse()?;
                Ok(CoinDataWrapper(CoinData {
                    covhash: dest,
                    value: amount,
                    denom: Denom::Mel,
                    additional_data: vec![],
                }))
            }
            [dest, amount, denom] => {
                let dest: CovHash = dest.parse()?;
                let amount: u128 = amount.parse()?;
                let denom: Vec<u8> = hex::decode(&denom)?;
                Ok(CoinDataWrapper(CoinData {
                    covhash: dest,
                    value: amount,
                    denom: Denom::from_bytes(&denom).context("invalid denomination")?,
                    additional_data: vec![],
                }))
            }
            &[dest, amount, denom, additional_data] => {
                let dest: CovHash = dest.parse()?;
                let amount: u128 = amount.parse()?;
                let denom: Vec<u8> = hex::decode(&denom)?;
                let additional_data: Vec<u8> = hex::decode(&additional_data)?;
                Ok(CoinDataWrapper(CoinData {
                    covhash: dest,
                    value: amount,
                    denom: Denom::from_bytes(&denom).context("invalid denomination")?,
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
                    .create_wallet(&wargs.wallet, testnet, Some(pwd))
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
            Args::AddCoin { wargs, coin } => {
                wargs.wallet().await?.add_coin(coin).await?;
                writeln!(twriter, "Coin successfully added!")?;
                let summary = wargs.wallet().await?.summary().await?;
                write_wallet_summary(&mut twriter, &wargs.wallet, &summary)?;
            }
            Args::SendTx { wargs, to, secret } => {
                let wallet = wargs.wallet().await?;
                let secret = secret
                    .map(|secret| Ed25519SK(hex::decode(&secret).unwrap().try_into().unwrap()));
                let desired_outputs = to.iter().map(|v| v.0.clone()).collect::<Vec<_>>();
                let tx = wallet
                    .prepare_transaction(desired_outputs.clone(), secret)
                    .await?;
                writeln!(twriter, "{}", "TRANSACTION RECIPIENTS".bold())?;
                writeln!(twriter, "{}", "Address\tAmount\tAdditional data".italic())?;
                for output in desired_outputs {
                    writeln!(
                        twriter,
                        "{}\t{} {}\t{:?}",
                        output.covhash.to_string().bright_blue(),
                        output.value,
                        match output.denom {
                            Denom::Mel => "µMEL",
                            Denom::Sym => "µSYM",
                            Denom::NomDosc => "µnomDOSC",
                            Denom::Custom(_) => "(custom token)",
                            Denom::NewCoin => "(new token type)",
                        },
                        hex::encode(&output.additional_data)
                    )?;
                }
                writeln!(
                    twriter,
                    "{}\t{} µMEL",
                    " (network fees)".yellow(),
                    tx.fee.to_string()
                )?;
                twriter.flush()?;
                eprint!("Proceed? [y/N] ");
                let mut letter = [0u8; 1];
                stdin.read_exact(&mut letter).await?;
                if letter[0] == 0x79 {
                    let txhash = wallet.send_tx(tx).await?;
                    write_txhash(&mut twriter, &wargs.wallet, txhash)?;
                }
            }
            Args::WaitConfirmation { wargs, txhash } => loop {
                let wallet = wargs.wallet().await?;
                let wallet_dump = wargs
                    .common
                    .dclient()
                    .dump_wallet(&wargs.wallet)
                    .await?
                    .unwrap();
                let status = wallet.get_transaction_status(TxHash(txhash)).await?;
                if let Some(height) = status.confirmed_height {
                    eprintln!("Confirmed at height {}", height);
                    eprintln!(
                        "(in block explorer: https://{}/blocks/{}/{})",
                        if wallet_dump.summary.network == NetID::Testnet {
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
            },
            Args::Unlock { wargs } => {
                let wallet = wargs.wallet().await?;
                eprint!("Enter password: ");
                let mut pwd = "".to_string();
                stdin.read_line(&mut pwd).await?;
                pwd.truncate(pwd.len() - 1);
                wallet.unlock(Some(pwd)).await?;
            }
            Args::Lock { wargs } => {
                let wallet = wargs.wallet().await?;
                wallet.lock().await?;
            }
        }
        twriter.flush()?;
        Ok(())
    })
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
        format!("{}\tµMEL", summary.total_micromel)
    )?;
    for (k, v) in summary.detailed_balance.iter() {
        let denom = match k.as_str() {
            "6d" => continue,
            "73" => "µSYM",
            "64" => "µnomDOSC",
            v => v,
        };
        writeln!(out, "\t{}\t{}", v, denom)?;
    }
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
