# melwallet-cli(ent)

[![](https://img.shields.io/crates/v/melwallet-client)](https://crates.io/crates/melwallet-client)
![](https://img.shields.io/crates/l/melwallet-client)

The de-facto cli interface for the canonical Mel wallet library, `melwallet`. `melwallet-cli` formats and send requests to the blockchain, prompting the user for when necessary. This tool aims to offer the flexibility of interacting directly with the `melwalletd` REST api with many additional benefits, including:

- useful help messages
- automatic response output formatting
- automatic transaction preparation and request formatting

## Installation

`melwallet-client` is a Rust crate, so the easiest way to install is with `cargo`:

```
cargo install --locked melwallet-cli
```

For a quick intro to using this software, check out [this quick guide](https://docs.melproject.org/developer-guides/using-wallets) in the Mel docs.

## Using melwallet-cli

To display a complete description of`melwallet-cli`'s capabilities, use the `--help` flag

```
$ melwallet-cli --help

Mel Wallet Command Line Interface

Usage: melwallet-cli --wallet-path <WALLET_PATH> <COMMAND>

Commands:
  create                 Create a wallet.  Ex: `melwallet-cli --wallet-path wallet123 create`
  send-faucet            Send a 1000 MEL faucet transaction for a testnet wallet
  summary                Details of a wallet
  send                   Send a transaction to the network
  pool                   Checks a pool.
  swap                   Swaps money from one denomination to another
  liq-deposit            Supplies liquidity to Melswap
  wait-confirmation      Wait for a particular transaction to confirm
  send-raw               Sends a raw transaction in hex, with no customization options
  export-sk              Exports the secret key of a wallet
  import-sk              Provide a secret key to import an existing wallet
  autoswap               Automatically executes arbitrage trades on the core, "triangular" MEL/SYM/ERG pairs
  stake                  Stakes a certain number of syms
  network-summary        
  generate-autocomplete  Generate bash autocompletions
  help                   Print this message or the help of the given subcommand(s)
```

As described above, all the functionality of melwallet-cli are available through the use of subcommands. Take a look inside one of the subcommands:

```
$ melwallet-cli send --help

Send a transaction to the network

Usage: melwallet-cli --wallet-path <WALLET_PATH> send [OPTIONS]

Options:
      --to <TO>                      FORMAT: `destination,amount[,denom[,additional_data]]`
                                     Specifies where to send funds; denom and additional_data are optional.
                                     For example, `--to $ADDRESS,100.0` sends 100 MEL to $ADDRESS.
                                     Amounts must be specified with numbers on either side of the decimal. Ex: 10.0, 0.1
                                     Can be specified multiple times to send money to multiple addresses.
                                     `denom` defaults to MEL
                                     `additional_data` must be hex encoded by default, but allows passsing ascii with `ascii=""`
      --force-spend <FORCE_SPEND>    Force the selection of a coin
      --add-covenant <ADD_COVENANT>  Additional covenants. This often must be specified if we are spending coins that belong to other addresses, like covenant coins
      --hex-data <HEX_DATA>          The contents of the data field, in hexadecimal [default: ]
      --dry-run                      Dumps the transaction as a hex string
      --wait                         Whether or not to wait for the the transaction to confirm
      --fee-ballast <FEE_BALLAST>    "Ballast" to add to the fee; 50 is plenty for an extra ed25519 signature added manually later [default: 0]
  -h, --help                         Print help
```

## Advanced Uses

`melwallet-cli` can used to deploy scripts, called covenants, onto Mel. Learn about deploying covenants [here](https://guide.melodeonlang.org/9_deploying_covenants.html).
