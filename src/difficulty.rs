use num_bigint::{BigUint,BigInt};
use num_rational::BigRational;
use num_traits::ToPrimitive;
use num_traits::{One, Zero};
use std::cmp::min;

const MAX_COMPACT: u32 = 0x207fffff;

fn bn256() -> BigUint {
    BigUint::one() << 256
}

// work = 2**256 / (target + 1)
fn work_for_tar(target: BigUint) -> BigUint {
    bn256() / (target + BigUint::one())
}

pub fn bn_for_compact(compact: u32) -> BigUint {
    let size = compact >> 24;
    if (compact & 0x00800000) != 0 {
        panic!("Negative bignum not supported");
    }
    let word = compact & 0x007fffff;
    if size <= 3 {
        BigUint::from(word >> (8 * (3 - size)))
    } else {
        BigUint::from(word) << (8 * (size - 3))
    }
}

fn compact_for_bn(bn: BigUint) -> u32 {
    let (compact, size) = {
        let size = {
            let bits = bn.bits() as u32;
            bits / 8 + if bits % 8 == 0 { 0 } else { 1 }
        };
        let compact = if size <= 3 {
            bn.to_u32().unwrap() << (8 * (3 - size))
        } else {
            (bn >> (8 * (size - 3))).to_u32().unwrap()
        };
        if compact & 0x00800000 != 0 {
            (compact >> 8, size + 1)
        } else {
            (compact, size)
        }
    };
    compact | (size << 24)
}

pub fn get_difficulty_ratio(bits: u32, pow_limit_bits: u32) -> f64 {
    let max = BigInt::from(bn_for_compact(pow_limit_bits));
    let target = BigInt::from(bn_for_compact(bits));
    let difficulty = BigRational::new(max, target);
    difficulty.to_f64().unwrap_or_else(|| {
        eprintln!("Cannot get difficulty");
        -1.0
    })
}

// diffOut = (2**256 - work) / work
fn tar_for_work(work: BigUint) -> BigUint {
    if work.is_zero() {
        bn256()
    } else if work.bits() > 256 {
        BigUint::zero()
    } else {
        (bn256() - &work) / work
    }
}

// effective_work = work**3 / 1024 / ann_work / ann_count**2
fn get_effective_work(
    blk_work: BigUint,
    ann_work: BigUint,
    ann_count: u64,
    pc_version: u64,
) -> BigUint {
    if ann_work.is_zero() || ann_count == 0 {
        // This is work *required* so when there is no work and no announcements
        // that work is "infinite".
        return bn256();
    }

    let mut out = blk_work.pow(3);
    
    if pc_version >= 2 {
        // difficulty /= 1024
        out >>= 10;
    }

    // workOut /= annWork
    out /= ann_work;

    if pc_version >= 2 {
        // workOut /= annCount**2
        out /= BigUint::from(ann_count).pow(2);
    } else {
        out /= BigUint::from(ann_count);
    }

    out
}

pub fn pc_get_effective_target(
    block_tar: u32,
    ann_tar: u32,
    ann_count: u64,
    pc_version: u64,
) -> u32 {
    let blk_work = work_for_tar(bn_for_compact(block_tar));
    let ann_work = work_for_tar(bn_for_compact(ann_tar));
    let effective_work = get_effective_work(blk_work, ann_work, ann_count, pc_version);
    let out = compact_for_bn(tar_for_work(effective_work));
    min(out, MAX_COMPACT)
}

