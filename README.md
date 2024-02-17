# PKT-Voter

This is a really simple PKT "wallet" which does one thing and one thing only: Cast votes.

A vote is a transaction which contains some additional metadata in an `OP_RETURN` output.
It doesn't need to have any particular amount of PKT in the vote itself, just enough to pay
the fees and return the coins back to the original address as change. The `OP_RETURN` output
containing the *actual* vote must, by rule, pay exactly zero PKT.

To use this app, you need to extract the *private key* from your wallet, a private key will
look something like this `cRTC8i8KwACJRAHh3BxmTnRcsy3FHZngNQv2ACYVcx6EBmBUptNi`.

From the private key, this tool is able to compute your address and it can create and sign
transations. Every wallet has one private key *per address*.

**NOTE:** Your private key is **SENSITIVE**, if you leak it, someone can steal the coins from
your address!

## Usage
To use this app, go to the [releases](https://github.com/cjdelisle/PKT-Voter/releases/latest)
page and download the appropriate version based on your system:

* Windows 64 bit: `PKT-Voter_windows_amd64.exe`
* Apple Silicon: `PKT-Voter_mac_aarch64.tar.bz2`
* Apple Intel: `PKT-Voter_mac_amd64.tar.bz2`
* Linux, you know this stuff: `PKT-Voter_linux_amd64.tar.bz2`

On Apple, you need to double-click on the `.tar.bz2` file to unpack it, and inside of it there
is a file called `PKT-Voter`. Hold the Apple command ⌘ key and right-click (i.e. 2 finger click)
on the file and select "open". You'll see a prompt warning you that the file came from an
unknown source, accept it and the app will open. If you don't use the command-key + right-click,
Apple will *not* allow you to open the program, but once you've opened it once, you'll be able
to just double-click on it after that.

On Windows you will also get a warning, which you can click through.

Once you have it open, you can export a private key from the wallet you use, paste it, and use
it to vote. See here for instructions: https://twitter.com/cjdelisle/status/1758198532870217927

## Compiling
If you're interested in playing with the code, you can compile it using Rust. You do NOT need
to do this just to use the program, this is only for developers.

1. Make sure you have Rust installed, see
[Rust Getting Started Guide](https://www.rust-lang.org/learn/get-started) if you don't.
2. Build and run the exectuable
    ```
    cargo run
    ```

This app is based on the [Slint](https://slint.rs) UI framework. Slint has a useful
[Language Server](https://github.com/slint-ui/slint/blob/master/tools/lsp/README.md) for exiting the UI
descriptor `.slint` files. If you use [Visual Studio Code](https://code.visualstudio.com), you can easily
install the [Slint extension](https://marketplace.visualstudio.com/items?itemName=Slint.slint) for syntax
highlighting and validation.

To learn more about the Slint APIs and the `.slint` markup language check out the
[online documentation](https://slint.dev/docs).