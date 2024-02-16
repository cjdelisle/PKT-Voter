use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::collections::BTreeMap;

use bitcoin::bech32::Hrp;
use bitcoin::bip32::DerivationPath;
use bitcoin::bip32::Fingerprint;
use bitcoin::consensus::encode;
use bitcoin::key::Secp256k1;
use bitcoin::key::secp256k1::{self, All};
use bitcoin::psbt;
use bitcoin::psbt::Input;
use bitcoin::psbt::PsbtSighashType;
use bitcoin::script::PushBytes;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::PubkeyHash;
use bitcoin::ScriptHash;
use bitcoin::ScriptBuf;
use bitcoin::address::Payload;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::hashes::Hash;
use miniscript::psbt::PsbtExt;

use anyhow::{bail,Result};
use slint::Weak;

mod explorer;
mod address;
mod packetcrypt;
mod difficulty;
mod types;

slint::include_modules!();

async fn get_usable_utxo(addr: &str) -> Result<(OutPoint,TxOut)> {
    let script = script_from_address(addr)?;
    let txn = explorer::get_transaction(addr).await?;
    for (n, txout) in txn.output.iter().enumerate() {
        // TODO: If the user has 2 TXOs in the same txn, one spent one unspent, this will
        //       possibly select the spent one.
        if txout.script_pubkey == script {
            return Ok((
                OutPoint{
                    txid: txn.txid(),
                    vout: n as u32,
                },
                txout.clone(),
            ))
        }
    }
    bail!("No usable txout found in selected transaction: {}", txn.txid());
}

fn amount_pkt(amt: &Amount) -> f64 {
    amt.to_sat() as f64 / 1073741824.0
}

fn encode_address_payload(payload: &bitcoin::address::Payload) -> String {
    bitcoin::address::AddressEncoding{
        payload: payload,
        // TODO config
        p2pkh_prefix: 0x75,
        p2sh_prefix: 0x38,
        hrp: Hrp::parse("pkt").unwrap(),
    }.to_string()
}

fn script_from_address(addr: &str) -> Result<bitcoin::ScriptBuf> {
    let prefix = match addr.rfind('1') {
        None => addr,
        Some(sep) => addr.split_at(sep).0,
    };
    if prefix == "pkt" {
        let (_hrp, version, data) = bitcoin::bech32::segwit::decode(addr)?;
        let version = bitcoin::WitnessVersion::try_from(version)?;
        let program = bitcoin::script::PushBytesBuf::try_from(data)?;
        let witness_program = bitcoin::WitnessProgram::new(version, program)?;
        let payload = Payload::WitnessProgram(witness_program);
        return Ok(payload.script_pubkey())
    }

    if addr.len() > 50 {
        bail!("Address is too long to be b58");
    }
    let data = bitcoin::base58::decode_check(addr)?;
    if data.len() != 21 {
        bail!("Base58 decode of address is not 21 bytes");
    }
    if data[0] == 0x75 {
        // p2pkh
        Ok(Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..])?).script_pubkey())
    } else if data[0] == 0x38 {
        // p2sh
        Ok(Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap()).script_pubkey())
    } else {
        bail!("First byte of decoded b58 not recognized");
    }
}

fn mk_vote_output(vote_for: Option<ScriptBuf>, is_candidate: bool) -> TxOut {
    let mut vote = if let Some(vf) = vote_for {
        let bytes = vf.as_bytes();
        let mut vote = vec![0_u8; bytes.len() + 1];
        vote[1..].copy_from_slice(bytes);
        vote
    } else {
        vec![0_u8]
    };
    vote[0] = if is_candidate { 1 } else { 0 };
    let pb: &PushBytes = vote[..].try_into().unwrap();
    TxOut{
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(pb),
    }
}

fn describe_txn(v: &psbt::Psbt) -> UiTransaction {
    let mut fees = Amount::ZERO;
    let mut inputs = Vec::new();
    for (input, txin) in v.inputs.iter().zip(v.unsigned_tx.input.iter()) {
        if let Some(wutxo) = &input.witness_utxo {
            // wutxo.script_pubkey
            let (address, _) = crate::address::encode_from_pkscript(&wutxo.script_pubkey);
            fees += wutxo.value;
            inputs.push(UiTxInput{
                amount: amount_pkt(&wutxo.value) as f32,
                prev_n: txin.previous_output.vout as i32,
                prev_txid: txin.previous_output.txid.to_string().into(),
                address: address.into(),
            });
        }
    }
    let mut outputs = Vec::new();
    for output in v.unsigned_tx.output.iter() {
        let (address, _) = crate::address::encode_from_pkscript(&output.script_pubkey);
        fees -= output.value;
        outputs.push(UiTxOutput{
            amount: amount_pkt(&output.value) as f32,
            address: address.into(),
        })
    }
    UiTransaction{
        inputs: inputs[..].into(),
        outputs: outputs[..].into(),
        total_fees: amount_pkt(&fees) as f32,
    }
}

fn sign_txn(ai: &AddrInfo, mut tx: psbt::Psbt, secp: &Secp256k1<All>) -> Result<bitcoin::Transaction> {

    // sign pbst
    let mut key_map = BTreeMap::new();
    key_map.insert(ai.public_key, ai.private_key);
    match tx.sign(&key_map, secp) {
        Ok(_) => {
            println!("Signing succeeded")
        },
        Err((_, error_map)) => {
            let mut errors = Vec::new();
            for (_, e) in error_map {
                errors.push(format!("Error: {e}"));
            } 
            bail!("Failed to sign transaction: {errors:?}");
        }
    }

    // finalize
    let tx = match tx.finalize(secp) {
        Ok(tx) => {
            println!("Finalizing succeeded");
            tx
        }
        Err((_, errors)) => {
            bail!("Failed to sign transaction: {errors:?}");
        }
    };

    let tx = tx.extract_tx_unchecked_fee_rate();
    println!("{}", encode::serialize_hex(&tx));

    Ok(tx)
}

//////

struct AddrInfo {
    private_key: bitcoin::PrivateKey,
    public_key: bitcoin::PublicKey,
    change_script: bitcoin::address::Payload,
    addr_str: String,
}

#[derive(Default)]
struct AppMut {
    addr_info: Option<AddrInfo>,
    spend_txout: Option<(bitcoin::OutPoint,TxOut)>,
    is_candidate: bool,
    vote_for: Option<ScriptBuf>,
    staged_txn: Option<psbt::Psbt>,
}

struct App {
    m: Mutex<AppMut>,
    ui: Weak<SlintApp>,
    secp: Secp256k1<All>,
    rt: tokio::runtime::Runtime,
}
unsafe impl Send for App {}
unsafe impl Sync for App {}

// latin plunge flip sound rule stay hedgehog someone jacket brick verb shallow

impl App {
    fn wif_key_to_address(self: &Arc<Self>, wif_key: &str) -> Result<AddrInfo> {
        // println!("Attempting to decode private key: {wif_key}");
        let data = bitcoin::base58::decode_check(wif_key)?;
        let compressed = match data.len() {
            33 => false,
            34 => true,
            _ => {
                bail!("Invalid key size");
            }
        };
        // println!("Made key: {data:?}");
        let sk = bitcoin::PrivateKey {
            compressed,
            network: bitcoin::Network::Bitcoin,
            inner: secp256k1::SecretKey::from_slice(&data[1..33])?,
        };
        let pk = sk.public_key(&self.secp);
        // println!("Made public key: {pk:?}");
        if let Ok(payload) = bitcoin::address::Payload::p2wpkh(&pk) {
            Ok(AddrInfo{
                private_key: sk,
                public_key: pk,
                addr_str: encode_address_payload(&payload),
                change_script: payload,
            })
        } else {
            bail!("Key is not valid p2wkph");
        }
    }
    async fn update_address_info(self: Arc<Self>, addr: AddrInfo) {
        let bal = explorer::get_balance(&addr.addr_str).await;
        let txn = get_usable_utxo(&addr.addr_str).await;
        self.m.lock().unwrap().addr_info = Some(addr);
        let ui = self.ui.clone();
        if let Err(e) = ui.upgrade_in_event_loop(move |ui| {
            match bal {
                Ok(balance) => {
                    ui.set_balance(format!("Balance: {balance}").into());
                    if balance > 0.0 {
                        match txn {
                            Ok(spend_txout) => {
                                let mut m = self.m.lock().unwrap();
                                m.spend_txout = Some(spend_txout);
                                ui.set_vote_ok(true);
                                ui.set_message("Please specify an address to vote for.".into());
                            }
                            Err(e) => {
                                ui.set_message(format!("Error getting transactions: {e}").into());
                            }
                        }
                    } else {
                        ui.set_message("Cannot vote with zero balance.".into());
                    }
                }
                Err(e) => {
                    ui.set_message(format!("Error getting balance: {e}").into());
                }
            }
        }) {
            println!("Warn: Unable to upgrade ui: {e}");
        }
    }
    fn make_vote(self: &Arc<Self>) -> Result<psbt::Psbt> {
        let m = self.m.lock().unwrap();
        let Some((op, txout)) = &m.spend_txout else {
            bail!("No outpoint, the app is in a wrong state");
        };
        let Some(ai) = &m.addr_info else {
            bail!("No address info, the app is in a wrong state");
        };
        let vote_for = &m.vote_for;
        let is_candidate = m.is_candidate;

        // Decide fee
        // We don't have a good way to choose a fee so we're going to pick 500 units
        // because that's over-paying by about double.
        let fee = Amount::from_sat(500);

        if txout.value < fee {
            bail!("Unable to make transaction because input is not enough to pay fee");
        }

        // make pbst
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn{
                previous_output: op.clone(),
                ..Default::default()
            }],
            output: vec![
                TxOut{
                    value: txout.value - fee,
                    script_pubkey: ai.change_script.script_pubkey(),
                },
                mk_vote_output(vote_for.clone(), is_candidate),
            ],
        };
        let mut tx = psbt::Psbt::from_unsigned_tx(tx)?;

        // update pbst
        tx.inputs = vec![Input {
            witness_utxo: Some(txout.clone()),
            redeem_script: Some({
                let Some(wpkh) = ai.public_key.wpubkey_hash() else {
                    bail!("public_key.wpubkey_hash() did not work correctly");
                };
                ScriptBuf::new_p2wpkh(&wpkh)
            }),
            sighash_type: Some(PsbtSighashType::from_str("SIGHASH_ALL")?),
            bip32_derivation: {
                // We need to create a key derivation path, even though we don't have one.
                // but it doesn't need to be meaningful because the signer will attempt to
                // get our privatekey directly from the pubkey if getting it from the path
                // fails.
                let mut map = BTreeMap::new();
                map.insert(ai.public_key.inner, (
                    Fingerprint::from([1u8, 2, 3, 42]),
                    DerivationPath::from_str("m/0'")?,
                ));
                map
            },
            ..Default::default()
        }];

        Ok(tx)
    }

    async fn bcast_txn(self: Arc<Self>, txn: bitcoin::Transaction) {
        let res = explorer::bcast_transaction(&txn).await;
        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            match res {
                Ok(()) => {
                    ui.set_sending(UiSending{
                        state: 1,
                        txid: txn.txid().to_string().into(),
                        message: "Transaction sent successfully".into(),
                        error: "".into(),
                    });
                }
                Err(e) => {
                    ui.set_sending(UiSending{
                        state: 2,
                        txid: txn.txid().to_string().into(),
                        message: "Failed to send transaction".into(),
                        error: format!("{e}").into(),
                    });
                }
            }
        });
    }
}

// cRTC8i8KwACJRAHh3BxmTnRcsy3FHZngNQv2ACYVcx6EBmBUptNi
// pkt1qsjwa38q0xm772689jav4k327j4rwcrg9aftu9t

fn main() -> Result<()> {
    let ui = SlintApp::new()?;
    let app = Arc::new(App {
        m: Default::default(),
        ui: ui.as_weak(),
        secp: Secp256k1::new(),
        rt: tokio::runtime::Runtime::new()?,
    });

    ui.on_compute_address({
        let app = Arc::clone(&app);
        move || {
            let ui = app.ui.upgrade().unwrap();
            let sk = ui.get_private_key();
            match app.wif_key_to_address(&sk) {
                Ok(s) => {
                    println!("Got address: {}", s.addr_str);
                    ui.set_address(format!("Address: {}", s.addr_str).into());
                    ui.set_balance("Balance: Loading...".into());
                    ui.set_message("Got address, loading balance...".into());
                    app.rt.spawn(Arc::clone(&app).update_address_info(s));
                }
                Err(e) => {
                    ui.set_message(format!("Private key error: {e}").into());
                }
            }
        }
    });

    ui.on_check_vote_for_address({
        let app = Arc::clone(&app);
        move || {
            let ui = app.ui.upgrade().unwrap();
            let vfn = ui.get_vote_for_nobody();
            let is_candidate = ui.get_is_candidate();
            if vfn {
                let mut m = app.m.lock().unwrap();
                m.is_candidate = is_candidate;
                m.vote_for = None;
                ui.set_vote_for_ok(true);
                ui.set_message("Ready to vote".into());
                return;
            }
            let addr = ui.get_vote_for();
            if addr.is_empty() {
                ui.set_message("Please specify an address to vote for.".into());
                return;
            }
            match script_from_address(&addr) {
                Ok(scr) => {
                    let mut m = app.m.lock().unwrap();
                    m.is_candidate = is_candidate;
                    m.vote_for = Some(scr);
                    ui.set_vote_for_ok(true);
                    ui.set_message("Ready to vote".into());
                }
                Err(e) => {
                    ui.set_vote_for_ok(false);
                    ui.set_message(format!("Unable to handle vote for address: {e}").into());
                }
            }
        }
    });

    ui.on_compute_vote({
        let app = Arc::clone(&app);
        move || {
            let ui = app.ui.upgrade().unwrap();
            match app.make_vote() {
                Ok(psbt) => {
                    let desc = describe_txn(&psbt);
                    app.m.lock().unwrap().staged_txn = Some(psbt);
                    ui.set_confirm_txn(desc);
                    ui.set_window(1);
                }
                Err(e) => {
                    ui.set_message(format!("Error creating vote: {e}").into());
                }
            }
        }
    });

    ui.on_confirm_cancel({
        let app = Arc::clone(&app);
        move || {
            println!("on_confirm_cancel");
            let ui = app.ui.upgrade().unwrap();
            app.m.lock().unwrap().staged_txn = None;
            ui.set_window(0);
        }
    });

    ui.on_confirm_ok({
        let app = Arc::clone(&app);
        move || {
            let ui = app.ui.upgrade().unwrap();
            ui.set_sending(UiSending{
                state: 0,
                txid: "".into(),
                message: "Signing transaction".into(),
                error: "".into(),
            });
            ui.set_window(2);

            let mut m = app.m.lock().unwrap();
            let Some(psbt) = m.staged_txn.take() else {
                ui.set_sending(UiSending{
                    state: 2,
                    txid: "".into(),
                    message: "".into(),
                    error: "No staged transaction, app in wrong state".into(),
                });
                return;
            };
            let Some(ai) = &m.addr_info else {
                ui.set_sending(UiSending{
                    state: 2,
                    txid: "".into(),
                    message: "".into(),
                    error: "No address info, app in wrong state".into(),
                });
                return;
            };
            let tx = match sign_txn(ai, psbt, &app.secp) {
                Ok(txn) => txn,
                Err(e) => {
                    ui.set_sending(UiSending{
                        state: 2,
                        txid: "".into(),
                        message: "".into(),
                        error: format!("Failed to sign transaction: {e}").into(),
                    });
                    return;
                }
            };
            ui.set_sending(UiSending{
                state: 0,
                txid: tx.txid().to_string().into(),
                message: "Transaction signed, uploading...".into(),
                error: "".into(),
            });
            println!("Tx content: {}", encode::serialize_hex(&tx));
            app.rt.spawn(Arc::clone(&app).bcast_txn(tx));
        }
    });

    ui.on_sending_done({
        let app = Arc::clone(&app);
        move || {
            let ui = app.ui.upgrade().unwrap();
            app.m.lock().unwrap().staged_txn = None;
            ui.set_window(0);
        }
    });

    ui.run()?;
    Ok(())
}
