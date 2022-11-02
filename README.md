# melwallet-cli

[![](https://img.shields.io/crates/v/melwallet-client)](https://crates.io/crates/melwallet-client)
![](https://img.shields.io/crates/l/melwallet-client)


The defacto tool used to communicate with the Themelio wallet daemon, [`melwalletd`](https://github.com/themeliolabs/melwalletd). `melwallet-cli`  formats and send requests to the blockchain, prompting the user for when necessary. This tool aims to offer the flexibility of interacting directly with the `melwalletd` REST api with many additional benefits, including:

+ useful help messages 
+ automatic response output formatting
+ automatic transaction preparation and request formatting


## Installation

`melwallet-client` is a rust crate so the easiest way to install is with `cargo`. If not already installed, be sure to also install `melwalletd`

``` 
cargo install --locked melwallet-cli melwalletd
```

For a quick intro to using this software, checkout [this quick guide] on the Themelio docs page(https://docs.themelio.org/try-themelio/my-first-tx/)



## Using melwallet-cli

To find out about `melwallet-cli`s capabilities, use the `--help` flag 

``` 
$ melwallet-cli --help

melwallet-client

USAGE:
    melwallet-cli <SUBCOMMAND>

OPTIONS:
    -h, --help    Print help information

SUBCOMMANDS:
    autoswap                 Automatically executes arbitrage trades on the core, "triangular"
                                 MEL/SYM/NOM-DOSC pairs
    create                   Create a wallet
    export-sk                Exports the secret key of a wallet. Will read password from stdin
    generate-autocomplete    Generate bash autocompletions
    help                     Print this message or the help of the given subcommand(s)
    import                   Provide a secret key to import an existing wallet
    liq-deposit              Supplies liquidity to Melswap
    list                     List all available wallets
    lock                     Locks a wallet down again
    network-summary          Show the summary of the network connected to the associated
                                 melwalletd instance
    pool                     Checks a pool
    send                     Send a transaction to the network
    send-faucet              Send a 1000 MEL faucet transaction for a testnet wallet
    send-raw                 Sends a raw transaction in hex, with no customization options
    stake                    Stakes a certain number of syms
    summary                  Details of a wallet
    swap                     Swaps money from one denomination to another
    unlock                   Unlocks a wallet. Will read password from stdin
    wait-confirmation        Wait for a particular transaction to confirm

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

As a thin-client of `melwalletd`, `melwallet-cli` needs access to an instance of `melwalletd`. Learn how to run the wallet daemon on the docs page: https://docs.themelio.org/try-themelio/my-first-tx/. The rest of the documentation assumes `melwalletd` is running locally in the background.
### `create`

``` 
$ melwallet-cli create -w test_wallet
Enter password: <your password>
Wallet name:  test_wallet (locked)
Network:      testnet
Address:      t20aexrbvnxgcpmyzbzcemv8651s40rqe0we8a33ebadyrhb87k930
Balance:      0.000000  MEL
Staked:       0.000000  SYM
```

As you can see here we used the `create` subcommand with the `-w` flag, short for `--wallet`, to create a wallet named `test_wallet`. This command outputs a formatted summary of the newly created wallet.


### `send-faucet` (testnet only)

```
$ melwallet-cli send-faucet -w test_wallet
Transaction hash:  c55cb04275fe0d6c618a51e04eb82b1a43487b499d8cca28d5d7ec2247f5047d
(wait for confirmation with melwallet-cli wait-confirmation -w test_wallet c55cb04275fe0d6c618a51e04eb82b1a43487b499d8cca28d5d7ec2247f5047d)
```

When needed, 1001 fake `MEL` can be collected from the network using the `send-faucet` verb. This verb outputs the transaction hash, and a `melwallet-cli` command using the `wait-confirmation` verb. 

```
melwallet-cli wait-confirmation -w test_wallet c55cb04275fe0d6c618a51e04eb82b1a43487b499d8cca28d5d7ec2247f5047d
```

If used, this command will cause the terminal to wait for a transaction to be accepted by the Themelio blockchain.



### `summary`

```
$ melwallet-cli summary -w test_wallet
Wallet name:  test_wallet (locked)
Network:      testnet
Address:      t20aexrbvnxgcpmyzbzcemv8651s40rqe0we8a33ebadyrhb87k930
Balance:      1001.000000  MEL
Staked:       0.000000     SYM
```

This command outputs a wallet summary for the wallet name specified by `-w`, `test_wallet`, consisting of the `network` this wallet belongs to, the `address` associated with this wallet, the `balance` (which contains `MEL` from a `send-faucet` transaction), and the amount of `SYM` staked on the network; identical to the summary produced by the verb, [`create`](#create)

### `send`

```
$ melwallet-cli send -w testing123 --to t22272fg9r0k8k09qj06drzzjq9e0rw3asxfs1zrnaccwv5j6gq5tg,0.0001,MEL,68656c6c6f20776f726c64
TRANSACTION RECIPIENTS
Address                                                 Amount          Additional data
t22272fg9r0k8k09qj06drzzjq9e0rw3asxfs1zrnaccwv5j6gq5tg  0.000100 MEL    "68656c6c6f20776f726c64"
t22272fg9r0k8k09qj06drzzjq9e0rw3asxfs1zrnaccwv5j6gq5tg  124.999685 MEL  ""
t22272fg9r0k8k09qj06drzzjq9e0rw3asxfs1zrnaccwv5j6gq5tg  124.999686 MEL  ""
 (network fees)                                         0.000254 MEL
Proceed? [y/N] y
Transaction hash:  818336401d0d1303d182aa83926f9d0fc288e12cdbf5d473327a255babed55f6
(wait for confirmation with melwallet-cli wait-confirmation -w testing123 818336401d0d1303d182aa83926f9d0fc288e12cdbf5d473327a255babed55f6)
```

The `--to` flag of the send command has four comma-delimitted fields; from the help doc:
```
FORMAT: "destination,amount[,denom[,additional_data]]"
```

+ `desination`: the wallet address to send funds
+ `amount`: A number requiring a decimal and numbers to either side of it; ex: 1.0, 0.01
+ `denom`: the type (denomination) of coin being sent; the native options are MEL,SYM, and ERG
+ `additional_data`: hex or ascii encoded data included in the transaction

In the above example the `additional_data` field, `68656c6c6f20776f726c64`, is the hex encoding of `hello world`. `melwallet-cli` is capable of encoding ascii strings as hex automatcally using `ascii=` like this
```

```
 Use `send --help` for 

```
FORMAT: "destination,amount[,denom[,additional_data]]"
```


```
melwallet-cli send --help
```


## Advanced Uses

`melwallet-cli` can also be used to deploy scripts, called covenants, on Themelio. Learn more about deploying covenants [here](https://guide.melodeonlang.org/9_deploying_covenants.html).