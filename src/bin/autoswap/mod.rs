use std::time::Duration;

use colored::Colorize;
use melwallet_client::{DaemonClient, WalletClient};
use themelio_stf::{CoinData, CoinValue, Denom, NetID, PoolKey, Transaction, TxKind};

use crate::wait_tx;

/// Execute arbitrage
pub async fn do_autoswap(daemon: DaemonClient, wallet: WalletClient, value: CoinValue) {
    loop {
        if let Err(err) = do_autoswap_once(&daemon, &wallet, value).await {
            eprintln!("cannot autoswap: {}", err.to_string().red())
        }
    }
}

async fn do_autoswap_once(
    daemon: &DaemonClient,
    wallet: &WalletClient,
    value: CoinValue,
) -> http_types::Result<()> {
    // first, we get the relevant pool states
    let is_testnet = wallet.summary().await?.network == NetID::Testnet;
    let ms_state = daemon
        .get_pool(PoolKey::new(Denom::Mel, Denom::Sym), is_testnet)
        .await?;
    let dm_state = daemon
        .get_pool(PoolKey::new(Denom::Mel, Denom::NomDosc), is_testnet)
        .await?;
    let ds_state = daemon
        .get_pool(PoolKey::new(Denom::Sym, Denom::NomDosc), is_testnet)
        .await?;
    // either m->s->d->m or m->d->s->m. these are the only two paths
    let msdm_payoff = {
        let syms = ms_state.clone().swap_many(value.0, 0).1;
        let doscs = ds_state.clone().swap_many(0, syms).0;
        dm_state.clone().swap_many(doscs, 0).1
    };
    let mdsm_payoff = {
        let doscs = dm_state.clone().swap_many(0, value.0).0;
        let syms = ds_state.clone().swap_many(doscs, 0).1;
        ms_state.clone().swap_many(0, syms).0
    };
    if msdm_payoff > value.0 {
        eprintln!("MSDM: {} => {} µMEL", value, msdm_payoff);
        execute_swap(wallet, Some(value), Denom::Mel, Denom::Sym).await?;
        execute_swap(wallet, None, Denom::Sym, Denom::NomDosc).await?;
        execute_swap(wallet, None, Denom::NomDosc, Denom::Mel).await?;
    } else if mdsm_payoff > value.0 {
        eprintln!("MDSM: {} => {} µMEL", value, mdsm_payoff);
        execute_swap(wallet, Some(value), Denom::Mel, Denom::NomDosc).await?;
        execute_swap(wallet, None, Denom::NomDosc, Denom::Sym).await?;
        execute_swap(wallet, None, Denom::Sym, Denom::Mel).await?;
    } else {
        eprintln!("No arbitrage opportunities!");
        smol::Timer::after(Duration::from_secs(60)).await;
    }
    Ok(())
}

async fn execute_swap(
    wallet: &WalletClient,
    from_value: Option<CoinValue>,
    from: Denom,
    to: Denom,
) -> http_types::Result<()> {
    let summary = wallet.summary().await?;
    let max_from_value = summary.detailed_balance[&hex::encode(&from.to_bytes())];
    let max_from_value = if from == Denom::Sym {
        max_from_value - summary.staked_microsym
    } else {
        max_from_value
    };
    let ms_swap = prepare_swap(wallet, from_value.unwrap_or(max_from_value), from, to).await?;
    let txhash = wallet.send_tx(ms_swap).await?;
    wait_tx(wallet, txhash).await?;
    smol::Timer::after(Duration::from_secs(1)).await;
    Ok(())
}

async fn prepare_swap(
    wallet: &WalletClient,
    from_value: CoinValue,
    from: Denom,
    to: Denom,
) -> http_types::Result<Transaction> {
    Ok(wallet
        .prepare_transaction(
            TxKind::Swap,
            vec![],
            vec![CoinData {
                value: from_value,
                denom: from,
                additional_data: vec![],
                covhash: wallet.summary().await?.address,
            }],
            vec![],
            PoolKey::new(from, to).to_bytes(),
            vec![],
        )
        .await?)
}
