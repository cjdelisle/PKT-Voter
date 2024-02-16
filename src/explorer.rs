use std::str::FromStr;

use bitcoin::consensus;
use anyhow::{bail,Result};
use serde::{Serialize,Deserialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct TransactionInput {
    pub address: String,
    pub value: String,
    pub spentcount: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransactionOutput {
    pub address: String,
    pub value: String,
    pub spentcount: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Transaction {
    pub txid: String,
    pub size: u32,
    pub vsize: u32,
    pub version: u32,
    pub locktime: u32,
    #[serde(rename = "inputCount")]
    pub input_count: u32,
    #[serde(rename = "outputCount")]
    pub output_count: u32,
    pub value: String,
    pub coinbase: String,
    #[serde(rename = "firstSeen")]
    pub first_seen: String,
    #[serde(rename = "dateMs")]
    pub date_ms: String,
    #[serde(rename = "blockTime")]
    pub block_time: String,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "blockHeight")]
    pub block_height: u32,
    pub input: Vec<TransactionInput>,
    pub output: Vec<TransactionOutput>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PagedData<T> {
    pub results: Vec<T>,
    pub prev: String,
    pub next: String,
}

pub async fn get_transaction_bin(txid: &str) -> Result<bitcoin::Transaction> {
    let bs = reqwest::get(&format!("https://explorer.cjdns.fr/api/v2/tx/{txid}/bin"))
        .await?
        .bytes()
        .await?;
    let txn = consensus::deserialize(&bs[..])?;
    Ok(txn)
}

pub async fn get_transaction(addr: &str) -> Result<bitcoin::Transaction> {
    // This will not spend mined coins, which makes life easier because we don't have to care
    // if they are not yet mature.
    let mut url = format!("https://explorer.pkt.cash/api/v1/PKT/pkt/address/{addr}/coins");
    loop {
        println!("Request: {url}");
        let bs = reqwest::get(&url)
            .await?
            .text()
            .await?;
        let txns: PagedData<Transaction> = serde_json::from_str(&bs)?;
        for txn in txns.results {
            if txn.block_hash.is_empty() {
                // Skip unconfirmed
                continue;
            }
            for out in txn.output.into_iter() {
                let value = u64::from_str(&out.value)?;
                if out.address != addr {
                    // Paying someone else
                    continue;
                }
                if out.spentcount != 0 {
                    // Already spent
                    continue;
                }
                if value < 500 {
                    // Unable to pay the fee
                    continue;
                }
                return get_transaction_bin(&txn.txid).await;
            }
        }
        url = txns.next;
        if url.is_empty() {
            bail!("No usable transactions found for address");
        }
    }
}

pub async fn get_balance(addr: &str) -> Result<f64> {
    #[derive(Deserialize,Debug)]
    struct Balance {
        pub balance: String,
    }
    println!("Make request");
    let bs = reqwest::get(
        format!("https://explorer.pkt.cash/api/v1/PKT/pkt/address/{addr}/balance"),
    )
        .await?
        .text()
        .await?;
    let bal: Balance = serde_json::from_str(&bs)?;
    println!("Got balance: {bal:?}");
    let balance = u64::from_str_radix(&bal.balance, 10)?;
    Ok((balance as f64) / 1073741824.0)
}

pub async fn bcast_transaction(txn: &bitcoin::Transaction) -> Result<()> {
    let real_txid = txn.txid().to_string();
    let txn_bytes = consensus::encode::serialize(txn);
    let bs = reqwest::Client::new()
        .post("https://explorer.cjdns.fr/api/v2/tx/bcast-bin")
        .body(reqwest::Body::from(txn_bytes))
        .send()
        .await?
        .text()
        .await?;
    let txid: String = match serde_json::from_str(&bs) {
        Ok(s) => s,
        Err(e) => {
            bail!("Error sending transaction: {e}");
        }
    };
    if txid != real_txid {
        bail!("Got back txid {txid} but was expecting {real_txid}");
    }
    Ok(())
}