use anyhow::{Result,bail};
use bitcoin::bech32::Hrp;
use bitcoin::blockdata::opcodes::OP_0;
use bitcoin::script::{Instruction, PushBytes};
use bitcoin::{Script, ScriptBuf};

use crate::types::VoteOld;

fn encode_address_payload(payload: &bitcoin::address::Payload) -> String {
    bitcoin::address::AddressEncoding{
        payload: payload,
        // TODO config
        p2pkh_prefix: 0x75,
        p2sh_prefix: 0x38,
        hrp: Hrp::parse("pkt").unwrap(),
    }.to_string()
}

fn parse_vote_part_old(vote: &PushBytes) -> Option<String> {
    if vote.is_empty() {
        None
    } else {
        let vf = bitcoin::script::ScriptBuf::from_bytes(vote.as_bytes().to_owned());
        let (vf, _) = encode_from_pkscript(&vf);
        Some(vf)
    }
}

fn parse_vote_old(
    vote_for: Option<Instruction>,
    vote_against: Option<Instruction>,
) -> Result<VoteOld> {
    let (vf, va) = match (vote_for, vote_against) {
        (Some(vf), Some(va)) => (vf, va),
        _ => bail!("OP_VOTE without 2 ops preceeding it"),
    };
    match (vf, va) {
        (Instruction::PushBytes(vf), Instruction::PushBytes(va)) => {
            Ok(VoteOld{
                for_option: parse_vote_part_old(vf),
                against_option: parse_vote_part_old(va),
            })
        }
        _ => bail!("OP_VOTE should have been prefixed by 2 pushes: {vote_for:?} / {vote_against:?}"),
    }
}

fn split_vote_old(
    scr: &bitcoin::script::Script,
) -> (bitcoin::script::ScriptBuf, Option<Result<VoteOld>>) {
    let mut insns = Vec::new();
    let mut vote = None;
    for insn in scr.instructions() {
        match insn {
            Ok(Instruction::Op(bitcoin::opcodes::all::OP_VERNOTIF)) => {
                let va = insns.pop();
                let vf = insns.pop();
                vote = Some(parse_vote_old(vf, va));
            }
            Ok(x) => insns.push(x),
            Err(e) => {
                return (ScriptBuf::from(scr), Some(Err(anyhow::anyhow!(e))));
            }
        }
    }
    let mut stripped = bitcoin::script::ScriptBuf::new();
    for insn in insns {
        stripped.push_instruction(insn);
    }
    (stripped, vote)
}

fn b64(b: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::engine::Engine;
    STANDARD.encode(b)
}

fn encode_script(scr: &[u8]) -> String {
    if scr.len() > 0 {
        let sb = ScriptBuf::from_bytes(scr.into());
        let (s, _) = encode_from_pkscript(&sb);
        s
    } else {
        "".into()
    }
}

fn render_pc_commit(d: &[u8]) -> String {
    if let Some(pcc) = crate::packetcrypt::parse_commit_data(d) {
        format!("diff:{}:count:{}:commit:{}",
            crate::difficulty::get_difficulty_ratio(pcc.ann_min_diff, 0x207fffff).round(),
            pcc.ann_count,
            pcc.ann_tree_commit_hash,
        )
    } else {
        format!("invalid:{}", hex::encode(d))
    }
}

fn render_segwit(d: &[u8]) -> String {
    if d.len() == 32 {
        hex::encode(d)
    } else {
        format!("invalid:{}", hex::encode(d))
    }
}

fn render_derp(d: &[u8]) -> String {
    String::from_utf8_lossy(d).to_string()
}

struct DataType {
    code: &'static[u8],
    name: &'static str,
    decoder: fn(&[u8]) -> String,
}
struct DataTypes(&'static[DataType]);
impl DataTypes {
    fn render_data(&self, d: &[u8]) -> String {
        if d.is_empty() {
            return "data:EMPTY".into()
        }
        for dt in self.0 {
            if let Some(d) = d.strip_prefix(dt.code) {
                return format!("data:{}:{}", dt.name, (dt.decoder)(d));
            }
        }
        format!("data:UNKNOWN:{}", hex::encode(d))
    }
}
const DATA_TYPES: DataTypes = DataTypes(&[
    DataType{ name: "VOTE",           code: &[0x00],                decoder: encode_script, },
    DataType{ name: "VOTE_CANDIDATE", code: &[0x01],                decoder: encode_script, },
    DataType{ name: "PACKETCRYPT",    code: &[0x09,0xf9,0x11,0x02], decoder: render_pc_commit, },
    DataType{ name: "SEGWIT",         code: &[0xaa,0x21,0xa9,0xed], decoder: render_segwit, },
    DataType{ name: "DERP",           code: &[0x69],                decoder: render_derp, },
]);

pub fn encode_from_pkscript(out: &bitcoin::script::ScriptBuf) -> (String, Option<Result<VoteOld>>) {
    match  bitcoin::Address::from_script(out.as_script(), bitcoin::Network::Bitcoin) {
        Ok(addr) => {
            return (encode_address_payload(&addr.payload()), None);
        }
        Err(_) => {}
    }
    // Try again but stripping any possible vote (old system)
    let (scr, vote) = split_vote_old(out);
    match  bitcoin::Address::from_script(scr.as_script(), bitcoin::Network::Bitcoin) {
        Ok(addr) => {
            return (encode_address_payload(&addr.payload()), vote);
        }
        Err(_) => {}
    }

    if scr.is_op_return() && scr.instructions().count() == 2 {
        if let Some(Ok(Instruction::PushBytes(bytes))) = scr.instructions().nth(1) {
            return (DATA_TYPES.render_data(bytes.as_bytes()), vote)
        }
    }
    (String::new() + "script:" + &b64(out.as_bytes()), vote)
}