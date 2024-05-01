mod persistent_truststore;
mod state;

use acidjson::AcidJson;
use anyhow::Context;
use autoswap::do_autoswap;
use base32::Alphabet;
use colored::{Color, ColoredString, Colorize};

use clap::{CommandFactory, Parser};

use melwallet::Wallet;

use once_cell::sync::Lazy;
use smol::process::Child;
use state::{State, WalletSummary};
use std::collections::BTreeMap;

use std::time::Duration;
use stdcode::StdcodeSerializeExt;

use std::io::{BufReader, Read, Stderr, Stdin};
use std::path::Path;

use melstructs::{BlockHeight, CoinValue, NetID, Transaction, TxHash};

use std::io::Write;
use std::sync::Mutex;
use tabwriter::TabWriter;
use tmelcrypt::Ed25519SK;
mod autoswap;
mod cli;

use clap_complete::{generate, shells::Bash};
use cli::{Args, SubcommandArgs};

use crate::state::WalletWithKey;
struct KillOnDrop(Option<Child>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
        }
    }
}

fn create_wallet(wallet_path: &str, network: NetID, secret: Ed25519SK) -> anyhow::Result<()> {
    let wallet_path = Path::new(&wallet_path);
    // check if a wallet already exists at this path
    let x: Result<AcidJson<WalletWithKey>, _> = AcidJson::open(wallet_path);
    if let Ok(_) = x {
        anyhow::bail!("A wallet already exists at this path");
    } else {
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
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    smolscale::block_on(async move {
        let mut twriter = TabWriter::new(std::io::stderr());
        let mut command = Args::command();
        let Args {
            wallet_path,
            subcommand,
            melnode_addr,
        } = Args::parse();

        // create wallet if that's the command, *before* we try to open it by creating the state
        match subcommand.clone() {
            SubcommandArgs::Create { network } => {
                let secret = Ed25519SK::generate();
                create_wallet(&wallet_path, network, secret)?;

                eprintln!("successfully created wallet at {}", wallet_path)
            }
            SubcommandArgs::ImportSk { secret, network } => {
                // We must reconstruct the secret key using the ed25519-dalek library
                let secret = base32::decode(Alphabet::Crockford, &secret)
                    .context("Failed to decode secret key")?;
                let secret = ed25519_dalek::SecretKey::from_bytes(&secret)
                    .context("Failed to create secret key")?;
                let public: ed25519_dalek::PublicKey = (&secret).into();
                let mut vv = [0u8; 64];
                vv[0..32].copy_from_slice(&secret.to_bytes());
                vv[32..].copy_from_slice(&public.to_bytes());
                let final_secret = Ed25519SK(vv);
                create_wallet(&wallet_path, network, final_secret)?;

                eprintln!("successfully imported wallet to {}", wallet_path)
            }
            _ => {}
        }

        // create melwallet-cli state
        let state = State::new(&wallet_path, melnode_addr).await?;
        // sync wallet with network
        state.sync_wallet().await?;
        // println!("finished syncing wallet!");
        match subcommand {
            SubcommandArgs::Create { network: _ } => {
                // we already created the wallet earlier
            }
            SubcommandArgs::SendFaucet { wait } => {
                let tx = state.prepare_faucet_tx().await?;
                state.send_raw(tx.clone()).await?;
                send_postamble(&tx, twriter, &wallet_path, &state, wait).await?;
            }
            SubcommandArgs::Summary => {
                let wallet_summary = state.wallet_summary().await?;
                write_wallet_summary(&mut twriter, wallet_summary)?;
            }
            SubcommandArgs::Send {
                to,
                force_spend,
                add_covenant,
                hex_data,
                dry_run,
                fee_ballast,
                wait,
            } => {
                let tx = state
                    .prepare_send_tx(to, force_spend, add_covenant, hex_data, fee_ballast)
                    .await?;
                // send transaction, or print if it's a dry run
                if dry_run {
                    eprintln!("{}", hex::encode(tx.stdcode()));
                } else {
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

                    // send
                    state.send_raw(tx.clone()).await?;
                    send_postamble(&tx, twriter, &wallet_path, &state, wait).await?;
                }
            }
            SubcommandArgs::Pool { pool } => {
                let pool_state = state.pool_info(pool).await?;
                let ratio = pool_state.lefts as f64 / pool_state.rights as f64;
                writeln!(
                    twriter,
                    "{} {}\t= {} {}",
                    "1".bold().bright_green(),
                    pool.left().to_string().italic(),
                    format!("{}", 1.0 / ratio).bold().yellow(),
                    pool.right().to_string().italic()
                )?;
                writeln!(
                    twriter,
                    "{} {}\t= {} {}",
                    "1".bold().yellow(),
                    pool.right().to_string().italic(),
                    format!("{}", ratio).bold().bright_green(),
                    pool.left().to_string().italic()
                )?;
                twriter.flush()?;
            }
            SubcommandArgs::Swap {
                value,
                from,
                to,
                wait,
            } => {
                let tx = state.prepare_swap_tx(value, from, to).await?;
                let to_value = state.swap_to_value(value, from, to).await?;

                // ask user if they really wanna do the swap
                writeln!(twriter, "{}", "SWAPPING".bold())?;
                writeln!(
                    twriter,
                    "From:\t{} {}",
                    value.to_string().bold().bright_green(),
                    from
                )?;
                writeln!(
                    twriter,
                    "To:\t{} {} (approximate)",
                    CoinValue(to_value).to_string().bold().yellow(),
                    to
                )?;
                twriter.flush()?;
                proceed_prompt().await?;

                // send tx
                state.send_raw(tx.clone()).await?;
                if wait {
                    wait_tx(&state, tx.hash_nosigs()).await?;
                }
            }
            SubcommandArgs::LiqDeposit {
                a_count,
                a_denom,
                b_count,
                b_denom,
                wait,
            } => {
                let tx = state
                    .prepare_liq_deposit_tx(a_count, a_denom, b_count, b_denom)
                    .await?;
                proceed_prompt().await?;
                state.send_raw(tx.clone()).await?;
                send_postamble(&tx, twriter, &wallet_path, &state, wait).await?;
            }
            SubcommandArgs::WaitConfirmation { txhash } => {
                wait_tx(&state, TxHash(txhash)).await?;
            }
            SubcommandArgs::SendRaw { txhex, wait } => {
                let tx: Transaction =
                    stdcode::deserialize(&hex::decode(&txhex).context("cannot decode hex")?)
                        .context("malformed transaction")?;
                proceed_prompt().await?;
                state.send_raw(tx.clone()).await?;
                send_postamble(&tx, twriter, &wallet_path, &state, wait).await?;
            }
            SubcommandArgs::ExportSk => {
                let sk = state.export_sk()?;
                writeln!(twriter, "{}", sk.bold().bright_blue(),)?;
            }
            SubcommandArgs::ImportSk {
                secret: _,
                network: _,
            } => {
                // we already imported the wallet earlier
            }
            SubcommandArgs::Autoswap { value } => {
                do_autoswap(value, &state).await;
            }
            SubcommandArgs::Stake {
                value: _,
                staker_pubkey: _,
                start: _,
                duration: _,
                wait: _,
            } => todo!("Staking is not supported yet!"),
            SubcommandArgs::NetworkSummary => {
                let header = state.latest_header().await?;
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
            }
            SubcommandArgs::GenerateAutocomplete => {
                generate(Bash, &mut command, "melwallet-cli", &mut std::io::stdout())
            }
        }
        Ok(())
    })
}

static STDIN_BUFFER: Lazy<Mutex<BufReader<Stdin>>> =
    Lazy::new(|| Mutex::new(BufReader::new(std::io::stdin())));

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

async fn send_postamble(
    tx: &Transaction,
    mut twriter: TabWriter<Stderr>,
    wallet_path: &str,
    state: &State,
    wait: bool,
) -> anyhow::Result<()> {
    if wait {
        wait_tx(state, tx.hash_nosigs()).await?;
    } else {
        let txhash = tx.hash_nosigs();
        writeln!(twriter, "Transaction hash:\t{}", txhash.to_string().bold())?;
        writeln!(
            twriter,
            "Wait for confirmation with: {}",
            format!(
                "melwallet-cli --wallet-path {} wait-confirmation {}",
                wallet_path, txhash
            )
            .bright_blue(),
        )?;
        twriter.flush()?;
    }

    Ok(())
}

fn write_wallet_summary(out: &mut impl Write, wallet_summary: WalletSummary) -> anyhow::Result<()> {
    writeln!(out, "Network:\t{}", wallet_summary.netid)?;
    writeln!(
        out,
        "Address:\t{}",
        wallet_summary.address.to_string().bright_blue()
    )?;

    writeln!(out, "Balances:")?;
    for (denom, value) in wallet_summary.detailed_balances {
        writeln!(out, "{value} {denom}")?;
    }

    writeln!(out, "Staked:\t{}\tSYM", wallet_summary.staked_microsym)?;

    Ok(())
}

async fn wait_tx(state: &State, txhash: TxHash) -> anyhow::Result<()> {
    while !state.tx_completed(txhash) {
        state.sync_wallet().await?;
        eprint!("{}", ".".yellow());
        smol::Timer::after(Duration::from_millis(500)).await;
    }
    eprintln!("Transaction {} confirmed!", txhash);
    Ok(())
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
