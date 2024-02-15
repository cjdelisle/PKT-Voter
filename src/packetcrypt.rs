// const endType = 0
// const pcpType = 1
// const signaturesType = 2
// const contentProofsType = 3
// const versionType = 4

use std::io::Read;

use anyhow::{self,bail,Result};
use bitcoin::consensus::Decodable;
use bitcoin::consensus::ReadExt;
use crate::types::{PcAnn,PcProof};

const TYPE_END: u64 = 0;
const TYPE_PCP: u64 = 1;
const TYPE_SIGNATURES: u64 = 2;
const TYPE_CONTENT_PROOFS: u64 = 3;
const TYPE_VERSION: u64 = 4;

const PC_ANN_SERIALIZE_SIZE: usize = 1024;
// const PC_ANN_HEADER_LEN: usize = 88;
// const PC_ANN_MERKLE_PROOF_LEN: usize = 896;
// const PC_ITEM4_PREFIX_LEN: usize = PC_ANN_SERIALIZE_SIZE - (PC_ANN_HEADER_LEN + PC_ANN_MERKLE_PROOF_LEN);

pub struct PacketCryptAnn {
    pub header: [u8; PC_ANN_SERIALIZE_SIZE],
}

impl PacketCryptAnn {
    pub fn get_version(&self) -> u32 {
        u32::from(self.header[0])
    }

    // pub fn get_announce_header(&self) -> &[u8] {
    //     &self.header[..PC_ANN_HEADER_LEN]
    // }

    // pub fn get_merkle_proof(&self) -> &[u8] {
    //     &self.header[PC_ANN_HEADER_LEN..PC_ANN_HEADER_LEN + PC_ANN_MERKLE_PROOF_LEN]
    // }

    // pub fn get_item4_prefix(&self) -> &[u8] {
    //     &self.header[PC_ANN_HEADER_LEN + PC_ANN_MERKLE_PROOF_LEN..]
    // }

    pub fn get_soft_nonce(&self) -> &[u8] {
        &self.header[1..4]
    }

    pub fn get_parent_block_height(&self) -> u32 {
        u32::from_le_bytes([
            self.header[12],
            self.header[13],
            self.header[14],
            self.header[15],
        ])
    }

    pub fn get_work_target(&self) -> u32 {
        u32::from_le_bytes([
            self.header[8],
            self.header[9],
            self.header[10],
            self.header[11],
        ])
    }

    pub fn get_content(&self) -> &[u8] {
        &self.header[20..56]
    }

    pub fn get_signing_key(&self) -> &[u8] {
        &self.header[56..88]
    }

    pub fn has_signing_key(&self) -> bool {
        !self.get_signing_key().iter().all(|&x| x == 0)
    }

    pub fn read(r: &mut impl std::io::Read) -> Result<Self> {
        let mut out = PacketCryptAnn{ header: [0_u8; PC_ANN_SERIALIZE_SIZE] };
        r.read_exact(&mut out.header[..])?;
        Ok(out)
    }

    pub fn to_pcann(&self) -> PcAnn {
        PcAnn {
            version: self.get_version(),
            soft_nonce: u32::from_le_bytes([
                self.get_soft_nonce()[0],
                self.get_soft_nonce()[1],
                self.get_soft_nonce()[2],
                0,
            ]),
            parent_block_height: self.get_parent_block_height(),
            work_target_hex: format!("{:08x}", self.get_work_target()),
            content_hex: {
                let content = self.get_content();
                let mut non_zero_bytes: Vec<u8> =
                    content.iter().rev().skip_while(|&&b| b == 0).cloned().collect();
                non_zero_bytes.reverse();
                hex::encode(&non_zero_bytes[..])
            },
            signing_key_hex: if self.has_signing_key() {
                hex::encode(self.get_signing_key())
            } else {
                "".into()
            },
        }
    }
}

pub struct PacketCryptProof {
    pub version: u64,
    pub length: usize,
    pub low_nonce: u32,
    pub anns: [PacketCryptAnn; 4],
    pub signatures: [Option<[u8; 64]>; 4],
    pub ann_merkle: Vec<u8>,
    pub content_proofs: Option<Vec<u8>>,
}
impl PacketCryptProof {
    pub fn to_pc_proof(&self) -> PcProof {
        PcProof{
            version: self.version,
            length: self.length,
            low_nonce: self.low_nonce,
            anns: self.anns.iter().map(|a|a.to_pcann()).collect(),
            signatures: if self.signatures.iter().any(|s|s.is_some()) {
                self.signatures.iter().map(|s|s.map(|s|hex::encode(&s[..]))).collect()
            } else {
                Vec::new()
            },
            ann_merkle: hex::encode(&self.ann_merkle[..]),
            content_proofs_hex: self.content_proofs.as_ref().map(|cp|hex::encode(&cp[..])),
        }
    }
}

pub fn parse_proof(r: &mut std::io::Cursor<&[u8]>) -> Result<PacketCryptProof> {
    let mut out = PacketCryptProof{
        version: 0,
        length: 0,
        low_nonce: 0,
        anns: [
            PacketCryptAnn{ header: [0_u8; PC_ANN_SERIALIZE_SIZE] },
            PacketCryptAnn{ header: [0_u8; PC_ANN_SERIALIZE_SIZE] },
            PacketCryptAnn{ header: [0_u8; PC_ANN_SERIALIZE_SIZE] },
            PacketCryptAnn{ header: [0_u8; PC_ANN_SERIALIZE_SIZE] },
        ],
        signatures: [None,None,None,None],
        ann_merkle: Vec::new(),
        content_proofs: None,
    };
    let mut has_pcp = false;
    loop {
        let t = bitcoin::VarInt::consensus_decode(r)?;
        let l = bitcoin::VarInt::consensus_decode(r)?;
        let size = t.size() + l.size() + l.0 as usize;
        match t.0 {
            TYPE_END => {
                out.length += size;
                if l.0 != 0 {
                    bail!("Invalid PcP: End is not zero length");
                }
                return Ok(out)
            }
            TYPE_PCP => {
                out.length += size;
                if l.0 <= (1024*4)+4 {
					bail!("Runt pcp, len [{}]", l.0);
				}
				if l.0 > 131072 {
				    bail!("Oversize pcp, len [{}]", l.0);
				}
                let mut r = r.take(l.0);
                out.low_nonce = r.read_u32()?;
                out.anns = [
                    PacketCryptAnn::read(&mut r)?,
                    PacketCryptAnn::read(&mut r)?,
                    PacketCryptAnn::read(&mut r)?,
                    PacketCryptAnn::read(&mut r)?,
                ];
                r.read_to_end(&mut out.ann_merkle)?;
                has_pcp = true;
            }
            TYPE_VERSION => {
                out.length += size;
                let mut r = r.take(l.0);
                let v = bitcoin::VarInt::consensus_decode(&mut r)?;
                if r.limit() > 0 {
                    bail!("Invalid PcP: Dangling bytes after the version");
                }
                out.version = v.0;
            }
            TYPE_CONTENT_PROOFS => {
                out.length += size;
                if !has_pcp {
                    bail!("Content proofs found before PcP");
                }
                let mut b = vec![0_u8; l.0 as usize];
                r.read_exact(&mut b[..])?;
                out.content_proofs = Some(b);
            }
            TYPE_SIGNATURES => {
                out.length += size;
                if !has_pcp {
                    bail!("Signatures found before PcP");
                }
                let mut signatures = [None,None,None,None];
                let mut r = r.take(l.0);
                for (i, ann) in out.anns.iter().enumerate() {
                    if ann.has_signing_key() {
                        let mut b = [0_u8; 64];
                        r.read_exact(&mut b[..])?;
                        signatures[i] = Some(b);
                    }
                }
                if r.limit() > 0 {
                    bail!("Invalid PcP: Dangling bytes after the signatures");
                }
                out.signatures = signatures;
            }
            _ => {
                // Any other data is ignored and discarded because it
                // doesn't get passed from one pktd to another.
                let mut b = vec![0_u8; l.0 as usize];
                r.read_exact(&mut b[..])?;
            }
        }
        // println!("PcP: Type {}, len: {}", t.0, l.0);

    }
}

pub struct PcCommit {
    pub ann_min_diff: u32,
    pub ann_tree_commit_hash: String,
    pub ann_count: u64,
}

pub fn parse_commit_data(rem: &[u8]) -> Option<PcCommit> {
    if rem.len() != 44 {
        return None
    }
    let mut ann_min_diff = [0_u8; 4];
    ann_min_diff.copy_from_slice(&rem[0..4]);
    let mut ann_count = [0_u8; 8];
    ann_count.copy_from_slice(&rem[36..]);
    Some(PcCommit{
        ann_min_diff: u32::from_le_bytes(ann_min_diff),
        ann_tree_commit_hash: hex::encode(&rem[4..36]),
        ann_count: u64::from_le_bytes(ann_count),
    })
}

pub fn parse_commit(b: &bitcoin::Block) -> Result<PcCommit> {
    let cb = b.coinbase().ok_or_else(||anyhow::anyhow!("Block [{}] missing coinbase", b.block_hash()))?;
    for txout in &cb.output {
        let b = txout.script_pubkey.as_bytes();
        if let Some(rem) = b.strip_prefix(b"\x6a\x30\x09\xf9\x11\x02") {
            if let Some(pcc) = parse_commit_data(rem) {
                return Ok(pcc);
            }
        }
    }
    bail!("No PacketCrypt commitment was found in the block");
}