use std::time::Duration;

use colored::Colorize;
use melstructs::{CoinValue, Denom, PoolKey};

use crate::{state::State, wait_tx};

/// Execute arbitrage
pub async fn do_autoswap(value: CoinValue, state: &State) {
    loop {
        if let Err(err) = do_autoswap_once(value, state).await {
            eprintln!("cannot autoswap: {}", err.to_string().red())
        }
    }
}

async fn do_autoswap_once(value: CoinValue, state: &State) -> anyhow::Result<()> {
    // first, we get the relevant pool states
    let ms_state = state
        .pool_info(PoolKey::new(Denom::Mel, Denom::Sym))
        .await?;
    let dm_state = state
        .pool_info(PoolKey::new(Denom::Mel, Denom::Erg))
        .await?;
    let ds_state = state
        .pool_info(PoolKey::new(Denom::Sym, Denom::Erg))
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
        eprintln!("MSEM: {} => {} MEL", value, CoinValue(msdm_payoff));
        let to_value_1 = execute_swap(value, Denom::Mel, Denom::Sym, state).await?;
        let to_value_2 = execute_swap(to_value_1, Denom::Sym, Denom::Erg, state).await?;
        execute_swap(to_value_2, Denom::Erg, Denom::Mel, state).await?;
    } else if mdsm_payoff > value.0 {
        eprintln!("MESM: {} => {} MEL", value, CoinValue(mdsm_payoff));
        let to_value_1 = execute_swap(value, Denom::Mel, Denom::Erg, state).await?;
        let to_value_2 = execute_swap(to_value_1, Denom::Erg, Denom::Sym, state).await?;
        execute_swap(to_value_2, Denom::Sym, Denom::Mel, state).await?;
    } else {
        eprintln!("No arbitrage opportunities!");
        smol::Timer::after(Duration::from_secs(60)).await;
    }
    Ok(())
}

/// returns how much `to` Denom was obtained
async fn execute_swap(
    from_value: CoinValue,
    from: Denom,
    to: Denom,
    state: &State,
) -> anyhow::Result<CoinValue> {
    eprintln!("(Swapping {} {} => {})", from_value, from, to);
    let to_value = state.swap_to_value(from_value, from, to).await?;
    let tx = state.prepare_swap_tx(from_value, from, to).await?;
    state.send_raw(tx.clone()).await?;

    wait_tx(state, tx.hash_nosigs()).await;
    smol::Timer::after(Duration::from_secs(1)).await;
    Ok(CoinValue(to_value))
}
