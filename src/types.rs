use serde::{Deserialize,Serialize};

#[derive(Debug,Serialize,Deserialize)]
pub struct Block {
    pub hash: String,
    pub confirmations: i64,
    pub strippedsize: i32,
    pub size: i32,
    pub weight: i32,
    pub height: i64,
    pub version: i32,
    #[serde(rename = "versionHex")]
    pub version_hex: String,
    pub merkleroot: String,
    pub tx: Option<Vec<String>>,
    #[serde(default)]
    pub rawtx: Vec<Tx>,
    pub time: u32,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    pub previousblockhash: String,
    pub nextblockhash: Option<String>,
    pub packetcryptproof: Option<String>,
    pub packetcryptversion: Option<i32>,
    pub packetcryptanncount: Option<u64>,
    pub packetcryptannbits: Option<String>,
    pub packetcryptanndifficulty: Option<f64>,
    pub packetcryptblkdifficulty: Option<f64>,
    pub packetcryptblkbits: Option<String>,
    pub sblockreward: String,
    pub networksteward: Option<String>,
    pub blocksuntilretarget: i32,
    pub retargetestimate: Option<f64>,
    pub pc_proof: Option<PcProof>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VoteOld {
    #[serde(rename = "for")]
    pub for_option: Option<String>,
    #[serde(rename = "against")]
    pub against_option: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TxOut {
    pub value: f64,
    pub svalue: String,
    pub n: u32,
    pub address: String,
    #[serde(default)]
    pub vote: Option<VoteOld>,
    pub vote_error: Option<String>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TxInCoinbase {
    pub coinbase: String,
    pub sequence: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScriptSig {
    pub asm: String,
    pub hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PrevOut {
    pub address: String,
    pub value: f64,
    pub svalue: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TxInNormal {
    pub txid: String,
    pub vout: u32,
    pub script_sig: Option<ScriptSig>,
    #[serde(default)]
    pub txin_witness: Option<Vec<String>>,
    #[serde(rename = "prevOut")]
    pub prevout: Option<PrevOut>,
    pub prev_addr: Option<String>,
    pub prev_addr_error: Option<String>,
    pub sequence: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TxIn {
    Coinbase(TxInCoinbase),
    Normal(TxInNormal),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Tx {
    //pub hex: String,
    pub txid: String,
    pub hash: String,
    pub size: u32,
    pub vsize: u32,
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct RpcBestBlock {
    pub hash: String,
    pub height: u32,
}

#[derive(Serialize,Deserialize,Clone,Debug)]
pub struct PcAnn {
    /// The ann version
    pub version: u32,

    /// The ann soft nonce
    pub soft_nonce: u32,

    /// The ann parent block height
    pub parent_block_height: u32,

    /// The hex representation of the ann work target
    pub work_target_hex: String,

    /// Hex of the content field if field is non-zero, with trailing zero bytes omitted
    pub content_hex: String,

    /// Signing key hex if field is non-zero, otherwise empty string
    pub signing_key_hex: String,
}

#[derive(Serialize,Deserialize,Debug)]
pub struct PcProof {
    /// The PacketCrypt version
    pub version: u64,

    /// Length of the cannonical PacketCrypt proof
    pub length: usize,

    /// Value of the low nonce
    pub low_nonce: u32,

    /// The 4 announcements
    pub anns: Vec<PcAnn>,

    /// The announcement signatures, if present
    pub signatures: Vec<Option<String>>,

    /// The announcement merkle proofs
    pub ann_merkle: String,

    /// The content proof hex if present
    pub content_proofs_hex: Option<String>,
}