use std::time::Duration;

use crate::wait_tx;
use anyhow::Context;
use colored::Colorize;
use melstructs::PoolKey;
use melstructs::{CoinData, CoinValue, Denom, Transaction, TxKind};
use melwalletd_prot::types::PrepareTxArgs;
use melwalletd_prot::MelwalletdClient;

/// Execute arbitrage
pub async fn do_autoswap(
    wallet_name: &str,
    value: CoinValue,
) {
    // loop {
    //     if let Err(err) = do_autoswap_once(&daemon, wallet_name, value).await {
    //         eprintln!("cannot autoswap: {}", err.to_string().red())
    //     }
    // }
todo!()
}

async fn do_autoswap_once(
    wallet_name: &str,
    value: CoinValue,
) -> anyhow::Result<()> {
    // // first, we get the relevant pool states
    // let ms_state = daemon
    //     .melswap_info(PoolKey::new(Denom::Mel, Denom::Sym))
    //     .await??
    //     .unwrap();
    // let dm_state = daemon
    //     .melswap_info(PoolKey::new(Denom::Mel, Denom::Erg))
    //     .await??
    //     .unwrap();
    // let ds_state = daemon
    //     .melswap_info(PoolKey::new(Denom::Sym, Denom::Erg))
    //     .await??
    //     .unwrap();
    // // either m->s->d->m or m->d->s->m. these are the only two paths
    // let msdm_payoff = {
    //     let syms = ms_state.clone().swap_many(value.0, 0).1;
    //     let doscs = ds_state.clone().swap_many(0, syms).0;
    //     dm_state.clone().swap_many(doscs, 0).1
    // };
    // let mdsm_payoff = {
    //     let doscs = dm_state.clone().swap_many(0, value.0).0;
    //     let syms = ds_state.clone().swap_many(doscs, 0).1;
    //     ms_state.clone().swap_many(0, syms).0
    // };
    // if msdm_payoff > value.0 {
    //     eprintln!("MSEM: {} => {} MEL", value, CoinValue(msdm_payoff));
    //     execute_swap(daemon, wallet_name, Some(value), Denom::Mel, Denom::Sym).await?;
    //     execute_swap(daemon, wallet_name, None, Denom::Sym, Denom::Erg).await?;
    //     execute_swap(daemon, wallet_name, None, Denom::Erg, Denom::Mel).await?;
    // } else if mdsm_payoff > value.0 {
    //     eprintln!("MESM: {} => {} MEL", value, CoinValue(mdsm_payoff));
    //     execute_swap(daemon, wallet_name, Some(value), Denom::Mel, Denom::Erg).await?;
    //     execute_swap(daemon, wallet_name, None, Denom::Erg, Denom::Sym).await?;
    //     execute_swap(daemon, wallet_name, None, Denom::Sym, Denom::Mel).await?;
    // } else {
    //     eprintln!("No arbitrage opportunities!");
    //     smol::Timer::after(Duration::from_secs(60)).await;
    // }
    // Ok(())
    todo!()
}

async fn execute_swap(
    wallet_name: &str,
    from_value: Option<CoinValue>,
    from: Denom,
    to: Denom,
) -> anyhow::Result<()> {
    // let summary = daemon.wallet_summary(wallet_name.into()).await??;
    // let max_from_value = summary
    //     .detailed_balance
    //     .get(&from.to_string())
    //     .context(format!("Couldn't find denom: {}", to))?
    //     .to_owned();
    // let max_from_value = if from == Denom::Sym {
    //     max_from_value - summary.staked_microsym
    // } else {
    //     max_from_value
    // };
    // let from_value = from_value.unwrap_or(max_from_value);
    // eprintln!("(swapping {} {} => {})", from_value, from, to);
    // let ms_swap = prepare_swap(daemon, wallet_name, from_value, from, to).await?;
    // let txhash = daemon.send_tx(wallet_name.into(), ms_swap).await??;
    // wait_tx(daemon, wallet_name, txhash).await?;
    // smol::Timer::after(Duration::from_secs(1)).await;
    // Ok(())
    todo!()
}

async fn prepare_swap(
    wallet_name: &str,
    from_value: CoinValue,
    from: Denom,
    to: Denom,
) -> anyhow::Result<Transaction> {
    todo!()
    // let summary = daemon.wallet_summary(wallet_name.into()).await??;
    // let ptx_args = PrepareTxArgs {
    //     kind: TxKind::Swap,
    //     inputs: vec![],
    //     outputs: vec![CoinData {
    //         value: from_value,
    //         denom: from,
    //         additional_data: Default::default(),
    //         covhash: summary.address,
    //     }],
    //     covenants: vec![],
    //     data: PoolKey::new(from, to).to_bytes().into(),
    //     nobalance: vec![],
    //     fee_ballast: 0,
    // };
    // let tx = daemon.prepare_tx(wallet_name.into(), ptx_args).await??;
    // Ok(tx)
}
