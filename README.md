# melwallet-cli

[![](https://img.shields.io/crates/v/melwallet-client)](https://crates.io/crates/melwallet-client)
![](https://img.shields.io/crates/l/melwallet-client)


The defacto tool used to communicate with the Themelio wallet daemon, [`melwalletd`](https://github.com/themeliolabs/melwalletd). `melwallet-cli`  formats and send requests to the blockchain, prompting the user for when neccessary. This tool aims to offer the flexiblity of interacting directly with the `melwalletd` REST api with many additional benefits, including:

+ useful help messages 
+ automatic response output formatting
+ automatic transaction preparation and request formatting


## Installation

`melwallet-client` is a rust crate so the easiest way to install is with `cargo`. If not already installed, be sure to also install `melwalletd`

``` 
cargo install --locked melwallet-cli melwalletd
```

For a quick intro to using this software, checkout [this quick guide] on the themelio docs page(https://docs.themelio.org/try-themelio/my-first-tx/)



## Using melwallet-cli

To find out about `melwallet-cli`s capabilities, use the `--help` flag 

``` 
$ melwallet-cli --help

melwallet-client x.x.x

USAGE:
    melwallet-cli <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    autoswap             Automatically executes arbitrage trades on the core, "triangular" MEL/SYM/ERG pairs
    create               Create a wallet
    export-sk            Exports the secret key of a wallet. Will read password from stdin
    help                 Prints this message or the help of the given subcommand(s)
    import               Provide a secret key to import an existing wallet
    liq-deposit          Supplies liquidity to Melswap
    list                 List all available wallets
    lock                 Locks a wallet down again
    pool                 Checks a pool
    send                 Send a transaction to the network
    send-faucet          Send a 1000 MEL faucet transaction for a testnet wallet
    stake                Stakes a certain number of syms
    summary              Details of a wallet
    swap                 Swaps money from one denomination to another
    unlock               Unlocks a wallet. Will read password from stdin
    wait-confirmation    Wait for a particular transaction to confirm
```

As described above, all the `melwalletd` endpoints are available through the use of subcommands. Taking a look inside one of the subcommands you'll see even more helpful messages 

```
$ melwallet-cli send --help

melwallet-cli-send x.x.x
Send a transaction to the network

USAGE:
    melwallet-cli send [FLAGS] [OPTIONS] -w <wallet>

FLAGS:
    -h, --help       Prints help information
        --raw
    -V, --version    Prints version information

OPTIONS:
        --add-covenant <add-covenant>...    Additional covenants. This often must be specified if we are spending coins
                                            that belong to other addresses, like covenant coins
        --endpoint <endpoint>               HTTP endpoint of a running melwalletd instance [default: 127.0.0.1:11773]
        --force-spend <force-spend>...      Force the selection of a coin
        --to <to>...                        A string specifying who to send money to, in the format
                                            "dest,amount[,denom[,additional_data]]". For example, --to $ADDRESS,1 sends
                                            1 µMEL to $ADDRESS. Can be specified multiple times to send money to
                                            multiple addresses
    -w <wallet>                             Name of the wallet to create or use

```

We are working all the time to make these messages as helpful as possible, if you have any suggestions please shoot us a line on [matrix](https://matrix.to/#/#general:matrix.themelio.org) or [discord](https://discord.gg/themelio)

## Basic Uses

### Creating a wallet

``` 
$ melwallet-cli create -w test_wallet
Enter password: <your password>
Wallet name:  test_wallet (locked)
Network:      testnet
Address:      t20aexrbvnxgcpmyzbzcemv8651s40rqe0we8a33ebadyrhb87k930
Balance:      0.000000  MEL
Staked:       0.000000  SYM
```

## Advanced Uses

`melwallet-cli` can also be used to deploy scripts, called covenants, on Themelio. Learn more about deploying covenants [here](https://guide.melodeonlang.org/9_deploying_covenants.html).