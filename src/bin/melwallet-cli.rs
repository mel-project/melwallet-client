use anyhow::Context;
use autoswap::do_autoswap;
use colored::{Color, ColoredString, Colorize};
use melwallet_client::{WalletClient, WalletSummary};

use clap::{CommandFactory, Parser};
use once_cell::sync::Lazy;
use smol::process::Child;
use std::collections::BTreeMap;
use std::io::{BufReader, Read, Stdin};
use std::sync::Mutex;
use std::{io::Write, time::Duration};
use stdcode::StdcodeSerializeExt;
use tabwriter::TabWriter;
use themelio_stf::{melvm::Covenant, PoolKey};
use themelio_structs::{
    CoinData, CoinValue, Denom, NetID, StakeDoc, Transaction, TxHash, TxKind, STAKE_EPOCH,
};
use tmelcrypt::Ed25519PK;
mod autoswap;
mod cli;

use clap_complete::{generate, shells::Bash};
use cli::{Args, CommonArgs};
struct KillOnDrop(Option<Child>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
        }
    }
}

static STDIN_BUFFER: Lazy<Mutex<BufReader<Stdin>>> =
    Lazy::new(|| Mutex::new(BufReader::new(std::io::stdin())));

async fn wait_tx(wallet: &WalletClient, txhash: TxHash) -> http_types::Result<()> {
    loop {
        let status = wallet.get_transaction_status(txhash).await?;
        if let Some(height) = status.confirmed_height {
            eprintln!("Confirmed at height {}", height);
            eprintln!(
                "(in block explorer: https://{}/blocks/{}/{})",
                if wallet.summary().await?.network == NetID::Testnet {
                    "scan-testnet.themelio.org"
                } else if wallet.summary().await?.network == NetID::Mainnet {
                    "scan.themelio.org"
                } else {
                    ""
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
        let mut twriter = TabWriter::new(std::io::stderr());
        let mut command = Args::command();
        let args = Args::from_args();
        if let Args::GenerateAutocomplete = args {
            generate(Bash, &mut command, "melwallet-cli", &mut std::io::stdout());
        };
        let command_output: (String, CommonArgs) = match args {
            Args::Create { wargs } => {
                let dclient = wargs.common.dclient();
                let pwd = enter_password_prompt().await?;
                dclient
                    .create_wallet(&wargs.wallet, Some(pwd), None)
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
                (serde_json::to_string_pretty(&summary)?, wargs.common)
            }
            Args::List(common) => {
                let dclient = common.dclient();
                let wallets = dclient.list_wallets().await?;
                // let mut wallets_json = "".to_string();
                for (name, summary) in wallets.clone() {
                    // let json_string = serde_json::to_string_pretty(&summary)?.to_owned();
                    // wallets_json +&&= &json_string;
                    write_wallet_summary(&mut twriter, &name, &summary)?;
                    writeln!(twriter)?;
                }
                (serde_json::to_string_pretty(&wallets)?, common)
            }
            Args::Summary(wallet) => {
                let summary = wallet.wallet().await?.summary().await?;
                write_wallet_summary(&mut twriter, &wallet.wallet, &summary)?;
                (serde_json::to_string_pretty(&summary)?, wallet.common)
            }
            Args::SendFaucet(wallet) => {
                let txhash = wallet.wallet().await?.send_faucet().await?;
                write_txhash(&mut twriter, &wallet.wallet, txhash)?;
                (serde_json::to_string_pretty(&txhash)?, wallet.common)
            }
            Args::Send {
                wargs,
                to,
                force_spend,
                add_covenant,
                dry_run,
                fee_ballast,
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
                        fee_ballast,
                    )
                    .await?;
                if dry_run {
                    println!("{}", hex::encode(tx.stdcode()));
                    (hex::encode(tx.stdcode()), wargs.common)
                } else {
                    send_tx(&mut twriter, wallet, tx.clone()).await?;
                    (serde_json::to_string_pretty(&tx)?, wargs.common)
                }
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
                let last_header = wargs.common.dclient().get_summary().await?;
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
                        syms_staked: value,
                        pubkey: staker_pubkey,
                    })
                    .await?;
                send_tx(&mut twriter, wallet, tx.clone()).await?;
                (serde_json::to_string_pretty(&tx)?, wargs.common)
            }
            Args::WaitConfirmation { wargs, txhash } => {
                wait_tx(&wargs.wallet().await?, TxHash(txhash)).await?;
                (serde_json::to_string_pretty(&txhash)?, wargs.common)
            }
            Args::Unlock { wargs } => {
                let wallet = wargs.wallet().await?;
                let pwd = enter_password_prompt().await?;
                wallet.unlock(Some(pwd)).await?;
                ("".into(), wargs.common)
            }
            Args::ExportSk { wargs } => {
                let wallet = wargs.wallet().await?;
                let pwd = enter_password_prompt().await?;
                let sk = wallet.export_sk(Some(pwd)).await?;
                writeln!(twriter, "{}", sk.bold().bright_blue(),)?;
                (serde_json::to_string_pretty(&sk)?, wargs.common)
            }
            Args::Lock { wargs } => {
                let wallet = wargs.wallet().await?;
                wallet.lock().await?;
                ("".into(), wargs.common)
            }
            Args::Pool { common, pool } => {
                let pool = pool.to_canonical().context("cannot canonicalize")?;
                let client = common.dclient();
                let pool_state = client.get_pool(pool).await?;
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
                (serde_json::to_string_pretty(&pool_state)?, common)
            }
            Args::Autoswap { wargs, value } => {
                let daemon = wargs.common.dclient();
                let wallet = wargs.wallet().await?;
                do_autoswap(daemon, wallet, value.into()).await;
                ("".into(), wargs.common)
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
                let value = value.unwrap_or(max_value);
                let pool_key = PoolKey::new(from, to);
                let to_send = wallet
                    .prepare_transaction(
                        TxKind::Swap,
                        vec![],
                        vec![CoinData {
                            value,
                            denom: from,
                            additional_data: vec![],
                            covhash: wallet.summary().await?.address,
                        }],
                        vec![],
                        pool_key.to_bytes(),
                        vec![],
                        0,
                    )
                    .await?;
                writeln!(twriter, "{}", "SWAPPING".bold())?;
                writeln!(
                    twriter,
                    "From:\t{} {}",
                    value.to_string().bold().bright_green(),
                    from
                )?;
                let dclient = wargs.common.dclient();
                let pool_state = dclient.get_pool(pool_key).await?;
                let to_value = if from == pool_key.right {
                    pool_state.clone().swap_many(0, value.0).0
                } else {
                    pool_state.clone().swap_many(value.0, 0).1
                };
                writeln!(
                    twriter,
                    "To:\t{} {} (approximate)",
                    CoinValue(to_value).to_string().bold().yellow(),
                    to
                )?;
                twriter.flush()?;
                proceed_prompt().await?;
                let txhash = wallet.send_tx(to_send.clone()).await?;
                write_txhash(&mut twriter, &wargs.wallet, txhash)?;
                if wait {
                    wait_tx(&wallet, txhash).await?
                }
                (serde_json::to_string_pretty(&to_send)?, wargs.common)
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
                                value: left_count,
                                denom: left_denom,
                                covhash,
                                additional_data: vec![],
                            },
                            CoinData {
                                value: right_count,
                                denom: right_denom,
                                covhash,
                                additional_data: vec![],
                            },
                        ],
                        vec![],
                        poolkey.to_bytes(),
                        vec![],
                        0,
                    )
                    .await?;
                send_tx(&mut twriter, wallet, tx.clone()).await?;
                (serde_json::to_string_pretty(&tx)?, wargs.common)
            }
            Args::Import { wargs, secret } => {
                let dclient = wargs.common.dclient();
                let pwd = enter_password_prompt().await?;
                dclient
                    .create_wallet(&wargs.wallet, Some(pwd), Some(secret))
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
                (serde_json::to_string_pretty(&summary)?, wargs.common)
            }
            Args::SendRaw { wargs, txhex } => {
                let wallet = wargs.wallet().await?;
                let tx: Transaction =
                    stdcode::deserialize(&hex::decode(&txhex).context("cannot decode hex")?)
                        .context("malformed transaction")?;

                send_tx(&mut twriter, wallet, tx.clone()).await?;
                (serde_json::to_string_pretty(&tx)?, wargs.common)
            }
            Args::NetworkSummary(args) => {
                let header = args.dclient().get_summary().await?;
                let header_string = serde_json::to_string_pretty(&header)?;

                let mut adhoc: BTreeMap<&str, serde_json::Value> =
                    serde_json::from_str(&header_string)?;

                let netid = header.network;
                let network = format_network(netid);
                writeln!(twriter, "Network: \t{network}")?;
                adhoc.remove("network");
                for (key, value) in adhoc.into_iter() {
                    let color_value = value.to_string();
                    let color_key = key.to_string();
                    writeln!(twriter, "{}: \t{}", color_key, color_value)?;
                }
                writeln!(twriter)?;
                (header_string, args)
            }
            _ => return Ok(()),
        };
        twriter.flush()?;

        if !command_output.1.raw {
            // std::io::stderr().write(&twriter.into_inner().unwrap()).context("writing output failed")?;
        } else {
            std::io::stdout().write_all(format!("{}\n", &command_output.0).as_bytes())?;
        }
        Ok(())
    })
}

async fn prompt_password(prompt: &str) -> anyhow::Result<String> {
    eprint!("{prompt}");
    let pwd = smol::unblock(|| match STDIN_BUFFER.lock().as_deref_mut() {
        Ok(buffer) => anyhow::Ok(rpassword::read_password_from_bufread(buffer).unwrap()),
        Err(_) => Err(anyhow::anyhow!("unknown buffer unlock problem")),
    })
    .await?;

    Ok(pwd.trim().to_string())
}

async fn enter_password_prompt() -> anyhow::Result<String> {
    prompt_password("Enter Password").await
}

async fn prompt_password_with_confirmation() -> anyhow::Result<String> {
    let pwd1 = prompt_password("Enter Password").await?;
    let pwd2 = prompt_password("Confirm password: ").await?;
    match pwd1 == pwd2 {
        true => Ok(pwd1),
        false => Err(anyhow::anyhow!("Passwords do not match")),
    }
}

fn format_network(netid: NetID) -> ColoredString {
    netid.to_string().to_uppercase().color(color_network(netid))
}
fn color_network(netid: NetID) -> Color {
    match netid {
        NetID::Mainnet => Color::Red,
        NetID::Testnet => Color::Green,
        _ => Color::Yellow,
    }
}
async fn send_tx(
    mut twriter: impl Write,
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
            output.denom,
            hex::encode(&output.additional_data)
        )?;
    }
    writeln!(twriter, "{}\t{} MEL", " (network fees)".yellow(), tx.fee)?;
    twriter.flush()?;
    proceed_prompt().await?;
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
    writeln!(out, "Network:\t{}", summary.network)?;
    writeln!(
        out,
        "Address:\t{}",
        summary.address.to_string().bright_blue()
    )?;
    writeln!(out, "Balance:\t{}\tMEL", summary.total_micromel)?;
    for (k, v) in summary.detailed_balance.iter() {
        let denom = match k.as_str() {
            "6d" => continue,
            "73" => "SYM",
            "64" => "ERG",
            v => v,
        };
        writeln!(out, "\t{}\t{}", v, denom)?;
    }
    writeln!(out, "Staked:\t{}\tSYM", summary.staked_microsym)?;
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

async fn proceed_prompt() -> anyhow::Result<()> {
    eprintln!("Proceed? [y/N] ");

    let letter = smol::unblock(move || {
        let mut letter = [0u8; 1];

        match STDIN_BUFFER.lock().as_deref_mut() {
            Ok(stdin) => {
                while letter[0].is_ascii_whitespace() || letter[0] == 0 {
                    // stdin.read_exact(&mut letter)
                    stdin.read_exact(&mut letter)?;
                }
                Ok(letter)
            }
            Err(_) => return Err(anyhow::anyhow!("unknown buffer unlock problem")),
        }
    })
    .await?;
    if letter[0].to_ascii_lowercase() != b'y' {
        anyhow::bail!("canceled");
    }
    Ok(())
}
