mod structs;

use acidjson::AcidJson;

use anyhow::Context;
use base32::Alphabet;
use colored::{Color, ColoredString, Colorize};

use clap::{CommandFactory, Parser};

use melprot::{Client, CoinChange};
use melwallet::{PrepareTxArgs, StdEd25519Signer, Wallet};

use bytes::Bytes;
use once_cell::sync::Lazy;
use smol::process::Child;
use smol::stream::StreamExt;
use std::collections::BTreeMap;
use stdcode::StdcodeSerializeExt;

use std::io::{BufReader, Read, Stdin};
use std::path::Path;

use melstructs::{BlockHeight, NetID, Transaction, TxHash};

use std::io::Write;
use std::sync::Mutex;
use tabwriter::TabWriter;
use tmelcrypt::Ed25519SK;
mod autoswap;
mod cli;

use clap_complete::{generate, shells::Bash};
use cli::Args;

use crate::structs::WalletWithKey;
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

async fn wait_tx(_wallet_name: &str, _txhash: TxHash) -> anyhow::Result<()> {
    todo!()
    // loop {
    //     let status = daemon
    //         .tx_status(wallet_name.into(), txhash.into())
    //         .await??
    //         .context(format!("Unable to find transaction: {}", txhash))?;
    //     if let Some(height) = status.confirmed_height {
    //         let summary = daemon.wallet_summary(wallet_name.into()).await??;
    //         eprintln!("Confirmed at height {}", height);
    //         eprintln!(
    //             "(in block explorer: https://{}/blocks/{}/{})",
    //             if summary.network == NetID::Testnet {
    //                 "testnet.melscan.io"
    //             } else if summary.network == NetID::Mainnet {
    //                 "melscan.io"
    //             } else {
    //                 ""
    //             },
    //             height,
    //             txhash
    //         );
    //         break;
    //     } else {
    //         eprint!("{}", ".".yellow());
    //         smol::Timer::after(Duration::from_secs(1)).await;
    //     }
    // }
    // Ok(())
}

async fn sync_wallet(wallet_path: &str) -> anyhow::Result<()> {
    let wwk: AcidJson<WalletWithKey> = AcidJson::open(Path::new(wallet_path))?;
    let wallet_address = wwk.read().wallet.address;
    let netid = wwk.read().wallet.netid;
    let client = melprot::Client::autoconnect(netid).await?;
    let latest_height = client.latest_snapshot().await?.current_header().height;

    if (latest_height.0 - wwk.read().wallet.height.0) < 100 {
        // we call `add_coins` unless we're too far out of sync with the network,
        // because downloading all the coins might take a while for wallets with lots of coins
        // and because we need to keep track of pending transactions.
        // For example, we don't want to:
        // 1. send a transaction (moves some coins into pending_outgoing)
        // 2. reset the wallet (clears pending_outgoing)
        // 3. immediately send another transaction that tries to use the same coins as the first transaction & fail

        let mut stream = client
            .stream_snapshots(wwk.read().wallet.height + BlockHeight(1))
            .take((latest_height.0 - wwk.read().wallet.height.0) as usize)
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

            println!(
                "calling wallet.add_coins... wallet.height = {} | snapshot.height = {}",
                wwk.read().wallet.height.0,
                snapshot.current_header().height
            );

            wwk.write().wallet.add_coins(
                snapshot.current_header().height,
                new_coins,
                spent_coins,
            )?;
        }
    } else {
        println!("yo yo resyncing everything");
        // resync everything
        let latest_snapshot = client.latest_snapshot().await?;
        if let Some(owned_coins) = latest_snapshot.get_coins(wallet_address).await? {
            // println!("we own {} coins!", owned_coins.len());
            // println!(
            //     "{}",
            //     serde_json::to_string(&owned_coins).context("cannot print out")?
            // );
            wwk.write()
                .wallet
                .full_reset(latest_snapshot.current_header().height, owned_coins)?
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    smolscale::block_on(async move {
        let mut twriter = TabWriter::new(std::io::stderr());
        let mut command = Args::command();
        let args = Args::parse();
        if let Args::GenerateAutocomplete = args {
            generate(Bash, &mut command, "melwallet-cli", &mut std::io::stdout());
        };
        match args {
            Args::Create { wargs, network } => {
                let wallet_path = Path::new(&wargs.wallet_path);
                let secret = Ed25519SK::generate();
                let cov = melvm::Covenant::std_ed25519_pk_new(secret.to_public());
                let addr = cov.hash();

                let wallet_with_key = WalletWithKey {
                    wallet: Wallet {
                        address: addr,
                        height: BlockHeight(0),
                        confirmed_utxos: BTreeMap::new(),
                        pending_outgoing: BTreeMap::new(),
                        netid: network,
                    },
                    secret_key: secret,
                };

                std::fs::write(wallet_path, serde_json::to_string(&wallet_with_key)?)?;
                println!("successfully created wallet");
            }
            Args::Summary(wargs) => {
                sync_wallet(&wargs.wallet_path).await?;
                println!("finished syncing wallet!");
                let wallet_with_key: AcidJson<WalletWithKey> =
                    AcidJson::open(Path::new(&wargs.wallet_path))?;
                write_wallet_summary(&mut twriter, &wallet_with_key.read().wallet)?;
            }
            Args::SendFaucet(wargs) => {
                // sync wallet with network
                sync_wallet(&wargs.wallet_path).await?;

                todo!()
                // let rpc_client = wargs.common.rpc_client();
                // let wallet_name = wargs.wallet;
                // let txhash = rpc_client.send_faucet(wallet_name.clone()).await??;
                // write_txhash(&mut twriter, &wallet_name, txhash)?;
                // serde_json::to_string_pretty(&txhash)?
            }
            Args::Send {
                wargs,
                to,
                force_spend,
                add_covenant,
                dry_run,
                fee_ballast,
                hex_data,
            } => {
                // sync wallet with network
                sync_wallet(&wargs.wallet_path).await?;
                println!("finished syncing!");
                // prepare transaction
                let wwk: AcidJson<WalletWithKey> = AcidJson::open(Path::new(&wargs.wallet_path))?;
                let netid = wwk.read().wallet.netid;
                let client = Client::autoconnect(netid).await?;

                let inputs = {
                    let mut v = vec![];
                    let wallet_height = wwk.read().wallet.height;
                    let snapshot = client.snapshot(wallet_height).await?;
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

                let signer = StdEd25519Signer(wwk.read().secret_key);
                let fee_multiplier = client
                    .latest_snapshot()
                    .await?
                    .current_header()
                    .fee_multiplier;
                let tx = wwk
                    .read()
                    .wallet
                    .prepare_tx(args, &signer, fee_multiplier)?;

                // send transaction, or print if it's a dry run
                if dry_run {
                    println!("{}", hex::encode(tx.stdcode()));
                } else {
                    send_tx(twriter, netid, &wargs.wallet_path, tx.clone()).await?;
                    wwk.write().wallet.add_pending(tx);
                }
            }
            Args::Stake {
                wargs: _,
                value: _,
                start: _,
                duration: _,
                staker_pubkey: _,
            } => {
                todo!("staking is not yet supported")
            }
            Args::WaitConfirmation { wargs, txhash } => {
                todo!()
            }
            Args::ExportSk { wargs } => {
                let wallet_with_key: AcidJson<WalletWithKey> =
                    AcidJson::open(&Path::new(&wargs.wallet_path))?;
                let secret = wallet_with_key.read().secret_key;
                let sk: String = base32::encode(Alphabet::Crockford, &secret.0[..32]);
                writeln!(twriter, "{}", sk.bold().bright_blue(),)?;
                twriter.flush()?;
            }
            Args::Pool { pool: _ } => {
                todo!()
                // let pool_state = rpc_client
                //     .melswap_info(pool)
                //     .await??
                //     .context("Couldn't find pool")?;
                // let ratio = pool_state.lefts as f64 / pool_state.rights as f64;
                // writeln!(
                //     twriter,
                //     "{} {}\t= {} {}",
                //     "1".bold().bright_green(),
                //     pool.left().to_string().italic(),
                //     format!("{}", 1.0 / ratio).bold().yellow(),
                //     pool.right().to_string().italic()
                // )?;
                // writeln!(
                //     twriter,
                //     "{} {}\t= {} {}",
                //     "1".bold().yellow(),
                //     pool.right().to_string().italic(),
                //     format!("{}", ratio).bold().bright_green(),
                //     pool.left().to_string().italic()
                // )?;
                // serde_json::to_string_pretty(&pool_state)?
            }
            Args::Autoswap { wargs: _, value: _ } => {
                todo!()
                // let wallet = wargs.wallet;
                // do_autoswap(rpc_client, &wallet, value.into()).await;
                // "".into()
            }
            Args::Swap {
                wargs: _,
                value: _,
                from: _,
                to: _,
                wait: _,
            } => {
                todo!()
                // let wallet_name = &wargs.wallet;
                // let wallet_summary = wargs.wallet().await?;

                // let max_value = *wallet_summary
                //     .detailed_balance
                //     .get(&from.to_string())
                //     .context(format!("no coins of denom: {}", from))?;
                // let max_value = if from == Denom::Mel {
                //     max_value / 2
                // } else {
                //     max_value
                // };
                // let value = value.unwrap_or(max_value);
                // let pool_key = PoolKey::new(from, to);
                // let ptx_args = PrepareTxArgs {
                //     kind: TxKind::Swap,
                //     inputs: vec![],
                //     outputs: vec![CoinData {
                //         value,
                //         denom: from,
                //         additional_data: vec![].into(),
                //         covhash: wallet_summary.address,
                //     }],
                //     covenants: vec![],
                //     data: pool_key.to_bytes().into(),
                //     nobalance: vec![],
                //     fee_ballast: 0,
                // };
                // let to_send = rpc_client
                //     .prepare_tx(wallet_name.clone(), ptx_args)
                //     .await??;
                // writeln!(twriter, "{}", "SWAPPING".bold())?;
                // writeln!(
                //     twriter,
                //     "From:\t{} {}",
                //     value.to_string().bold().bright_green(),
                //     from
                // )?;
                // let pool_state = rpc_client
                //     .melswap_info(pool_key)
                //     .await??
                //     .context(format!("could not find pool: {}", pool_key))?;
                // let to_value = if from == pool_key.right() {
                //     pool_state.clone().swap_many(0, value.0).0
                // } else {
                //     pool_state.clone().swap_many(value.0, 0).1
                // };
                // writeln!(
                //     twriter,
                //     "To:\t{} {} (approximate)",
                //     CoinValue(to_value).to_string().bold().yellow(),
                //     to
                // )?;
                // twriter.flush()?;
                // proceed_prompt().await?;
                // let txhash = rpc_client
                //     .send_tx(wallet_name.clone(), to_send.clone())
                //     .await??;
                // write_txhash(&mut twriter, &wargs.wallet, txhash)?;
                // if wait {
                //     wait_tx(&rpc_client, wallet_name, txhash).await?
                // }
                // serde_json::to_string_pretty(&to_send)?
            }
            Args::LiqDeposit {
                wargs: _,
                a_count: _,
                a_denom: _,
                b_count: _,
                b_denom: _,
            } => {
                todo!()
                // let wallet_summary = wargs.wallet().await?;
                // let wallet_name = &wargs.wallet;
                // let covhash = wallet_summary.address;
                // let poolkey = PoolKey::new(a_denom, b_denom);
                // let left_denom = poolkey.left();
                // let right_denom = poolkey.right();
                // let left_count = if left_denom == a_denom {
                //     a_count
                // } else {
                //     b_count
                // };
                // let right_count = if right_denom == a_denom {
                //     a_count
                // } else {
                //     b_count
                // };
                // let ptx_args = PrepareTxArgs {
                //     kind: TxKind::LiqDeposit,
                //     inputs: vec![],
                //     outputs: vec![
                //         CoinData {
                //             value: left_count,
                //             denom: left_denom,
                //             covhash,
                //             additional_data: vec![].into(),
                //         },
                //         CoinData {
                //             value: right_count,
                //             denom: right_denom,
                //             covhash,
                //             additional_data: vec![].into(),
                //         },
                //     ],
                //     covenants: vec![],
                //     data: poolkey.to_bytes().into(),
                //     nobalance: vec![],
                //     fee_ballast: 0,
                // };
                // let tx = rpc_client
                //     .prepare_tx(wallet_name.into(), ptx_args)
                //     .await??;
                // send_tx(&mut twriter, rpc_client, wallet_name, tx.clone()).await?;
                // (serde_json::to_string_pretty(&tx)?, wargs.common)
            }
            Args::ImportSk {
                wargs: _,
                secret: _,
            } => {
                //     let wallet_name = &wargs.wallet;
                //     let pwd = enter_password_prompt().await?;

                //     rpc_client
                //         .create_wallet(wallet_name.to_owned(), pwd, Some(secret))
                //         .await??;

                //     let summary = rpc_client.wallet_summary(wallet_name.to_owned()).await??;
                twriter.flush()?;
                //     write_wallet_summary(&mut twriter, wallet_name, &summary)?;
                //     writeln!(twriter)?;
                //     twriter.flush()?;
                //     (serde_json::to_string_pretty(&summary)?, wargs.common)
                // }
                // Args::SendRaw { wargs, txhex } => {
                //     let rpc_client = wargs.common.rpc_client();
                //     let wallet_name = &wargs.wallet;
                //     let tx: Transaction =
                //         stdcode::deserialize(&hex::decode(&txhex).context("cannot decode hex")?)
                //             .context("malformed transaction")?;

                //     send_tx(&mut twriter, rpc_client, wallet_name, tx.clone()).await?;
                //     (serde_json::to_string_pretty(&tx)?, wargs.common)
                // }
                // Args::NetworkSummary(common) => {
                //     let rpc_client = common.rpc_client();

                //     let header = rpc_client.latest_header().await??;
                //     let header_string = serde_json::to_string_pretty(&header)?;

                //     let mut adhoc: BTreeMap<&str, serde_json::Value> =
                //         serde_json::from_str(&header_string)?;

                //     let netid = header.network;
                //     let network = format_network(netid);
                //     writeln!(twriter, "Network: \t{network}")?;
                //     adhoc.remove("network");
                //     for (key, value) in adhoc.into_iter() {
                //         let color_value = value.to_string();
                //         let color_key = key.to_string();
                twriter.flush()?; //         writeln!(twriter, "{}: \t{}", color_key, color_value)?;
                                  //     }
                                  //     writeln!(twriter)?;
                                  //     (header_string, common)
            }
            _ => return Ok(()),
        };

        Ok(())
    })
}

async fn prompt_password(prompt: &str) -> anyhow::Result<String> {
    eprint!("{prompt}");
    let pwd = smol::unblock(rpassword::read_password).await?;

    Ok(pwd.trim().to_string())
}

async fn enter_password_prompt() -> anyhow::Result<String> {
    prompt_password("Enter Password: ").await
}

async fn prompt_password_with_confirmation() -> anyhow::Result<String> {
    let pwd1 = prompt_password("Enter Password: ").await?;
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
    network: NetID,
    wallet_path: &str,
    tx: Transaction,
) -> anyhow::Result<()> {
    // preamble
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

    // do stuff
    let client = Client::autoconnect(network).await?;
    let _ = client
        .latest_snapshot()
        .await?
        .get_raw()
        .send_tx(tx.clone())
        .await?;

    // postamble
    let txhash = tx.hash_nosigs();
    writeln!(twriter, "Transaction hash:\t{}", txhash.to_string().bold())?;
    writeln!(
        twriter,
        "(wait for confirmation with {})",
        format!(
            "melwallet-cli wait-confirmation -w {} {}",
            wallet_path, txhash
        )
        .bright_blue(),
    )?;
    twriter.flush()?;

    Ok(())
}

fn write_wallet_summary(out: &mut impl Write, wallet: &Wallet) -> anyhow::Result<()> {
    writeln!(
        out,
        "Address:\t{}",
        wallet.address.to_string().bright_blue()
    )?;
    writeln!(out, "Balance:")?;
    for (denom, value) in wallet.balances() {
        writeln!(out, "{value} {denom}")?;
    }

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
            Err(_) => Err(anyhow::anyhow!("unknown buffer unlock problem")),
        }
    })
    .await?;
    if letter[0].to_ascii_lowercase() != b'y' {
        anyhow::bail!("canceled");
    }
    Ok(())
}
