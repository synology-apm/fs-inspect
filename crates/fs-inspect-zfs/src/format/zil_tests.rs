//! The intent log's parts on bytes made here: the header's claim, old-format (ZILOG) blocks
//! with their chain at the end, and the records replay does not apply.

use super::*;
use crate::format::cksum::{Cksum, seal_embedded_with};

fn put(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// A claimed log ends at the claimed block, and at the claimed record only when the header
/// says that sequence is set; an unclaimed one has no end.
#[test]
fn a_claim_ends_the_walk_where_it_ended() {
    let mut b = vec![0u8; 168];
    put(&mut b, 0, 77); // claim txg
    put(&mut b, 8, 5); // replay seq
    put(&mut b, 144, 3); // claim block seq
    put(&mut b, 152, 0); // flags
    put(&mut b, 160, 41); // claim record seq
    let zh = ZilHeader::parse(&b, 0).unwrap();
    assert_eq!((zh.claim_txg, zh.replay_seq, zh.claim_blk_seq, zh.claim_lr_seq), (77, 5, 3, 41));
    assert!(zh.log.is_hole());
    assert_eq!(zh.ends(), (3, u64::MAX), "the record sequence is not marked valid");
    let valid = ZilHeader { flags: CLAIM_LR_SEQ_VALID, ..zh };
    assert_eq!(valid.ends(), (3, 41));
    let unclaimed = ZilHeader { claim_txg: 0, ..valid };
    assert_eq!(unclaimed.ends(), (u64::MAX, u64::MAX));
    // A header cut short does not parse.
    assert!(ZilHeader::parse(&b[..160], 0).is_err());
}

/// An old-format log block: records from its start, its chain (next pointer, bytes used,
/// checksum) at its end.
fn old_block(len: usize, nused: u64, verifier: &Cksum) -> Vec<u8> {
    let mut b = vec![0u8; len];
    for (i, x) in b[..64].iter_mut().enumerate() {
        *x = i as u8 + 1;
    }
    let base = len - CHAIN;
    put(&mut b, base + 136, nused);
    seal_embedded_with(alg::ZILOG, &mut b, len - ECK_SIZE, verifier);
    b
}

fn log_bp(a: u8, verifier: Cksum) -> BlkPtr {
    let mut bp = BlkPtr::default();
    bp.cksum_alg = a;
    bp.cksum = verifier;
    bp
}

/// An old-format (fletcher2, ZILOG) block verifies against its pointer's checksum and holds its
/// records from its start; its bytes used never reach into the chain; another verifier, or a
/// changed byte, and the block does not verify (the chain ends there).
#[test]
fn an_old_format_block_has_its_chain_at_the_end() {
    let v: Cksum = [0x1234, 0x5678, 0x9abc, 7];
    let bp = log_bp(alg::ZILOG, v);
    let b = old_block(4096, 64, &v);
    let got = verified(&bp, b.clone()).expect("verifies");
    assert_eq!(got.records, 0..64);
    assert!(got.next.is_hole(), "the last block of its chain");
    assert_eq!(&got.bytes[..64], &b[..64]);

    let mut long = old_block(4096, 1 << 20, &v);
    assert_eq!(verified(&bp, long.clone()).unwrap().records, 0..4096 - CHAIN, "bytes used past the chain");
    long[10] ^= 1;
    assert!(verified(&bp, long).is_none(), "a changed record");
    assert!(verified(&log_bp(alg::ZILOG, [1, 2, 3, 4]), b.clone()).is_none(), "another block's verifier");
    assert!(verified(&bp, vec![0; CHAIN - 1]).is_none(), "shorter than its chain");
}

/// A ZILOG2 block's bytes used must hold its chain and stay within the block.
#[test]
fn a_new_format_block_needs_its_bytes_used_within_it() {
    let v: Cksum = [9, 8, 7, 1];
    let bp = log_bp(alg::ZILOG2, v);
    let make = |nused: u64| {
        let mut b = vec![0u8; 4096];
        put(&mut b, 136, nused);
        seal_embedded_with(alg::ZILOG2, &mut b, CHAIN - ECK_SIZE, &v);
        b
    };
    assert_eq!(verified(&bp, make(CHAIN as u64 + 32)).unwrap().records, CHAIN..CHAIN + 32);
    assert!(verified(&bp, make(CHAIN as u64 - 1)).is_none(), "used bytes inside the chain");
    assert!(verified(&bp, make(4097)).is_none(), "used bytes past the block");
}

/// A record of `len` bytes with the words `w` from offset 32.
fn rec(len: usize, w: &[u64]) -> Vec<u8> {
    let mut r = vec![0u8; len];
    for (i, &x) in w.iter().enumerate() {
        put(&mut r, 32 + 8 * i, x);
    }
    r
}

/// The records replay does not apply still name the objects they change (the object field's
/// top byte, a dnode's slot count, left out); write2 says how far the file grows; an unknown
/// type or a record cut short fails.
#[test]
fn records_replay_does_not_apply_name_their_objects() {
    let slots = 3u64 << 56;
    let r = rec(64, &[slots | 12, 4096, 8192]);
    assert_eq!(Lr::parse(tx::WRITE2, &r, 0).unwrap(), Lr::Write2 { obj: 12, offset: 4096, length: 8192 });
    let r = rec(64, &[34, slots | 35]);
    for t in [
        tx::MKXATTR,
        tx::CREATE_ACL,
        tx::CREATE_ATTR,
        tx::CREATE_ACL_ATTR,
        tx::MKDIR_ACL,
        tx::MKDIR_ATTR,
        tx::MKDIR_ACL_ATTR,
    ] {
        assert_eq!(Lr::parse(t, &r, 0).unwrap(), Lr::Other { objects: vec![34, 35] }, "type {t}");
    }
    for t in [tx::RENAME_EXCHANGE, tx::RENAME_WHITEOUT] {
        assert_eq!(Lr::parse(t, &r, 0).unwrap(), Lr::Other { objects: vec![34, slots | 35] }, "type {t}");
    }
    let r = rec(64, &[slots | 50]);
    for t in [tx::ACL_V0, tx::ACL, tx::SETSAXATTR, tx::CLONE_RANGE] {
        assert_eq!(Lr::parse(t, &r, 0).unwrap(), Lr::Other { objects: vec![50] }, "type {t}");
    }
    assert!(Lr::parse(tx::MAX, &r, 0).is_err(), "an unknown type");
    assert!(Lr::parse(tx::WRITE2, &r[..48], 0).is_err(), "write2 cut short");
    assert!(Lr::parse(tx::SETATTR, &r, 0).is_err(), "setattr cut short");
}

/// Names end at their NUL: one missing, or a name starting past the record, fails the record.
#[test]
fn record_names_must_end_within_the_record() {
    let mut r = rec(44, &[4]);
    r[40..44].copy_from_slice(b"name");
    assert!(Lr::parse(tx::REMOVE, &r, 0).is_err(), "no NUL");
    r.push(0);
    assert_eq!(Lr::parse(tx::RMDIR, &r, 0).unwrap(), Lr::Remove { dir: 4, name: b"name".to_vec() });
    assert!(Lr::parse(tx::LINK, &rec(48, &[4, 9]), 0).is_err(), "no name at the record's end");
    // A symlink's target is a second name after the first.
    let mut r = rec(104, &[1, 2]);
    r.extend_from_slice(b"ln\0target");
    assert!(Lr::parse(tx::SYMLINK, &r, 0).is_err(), "the target without its NUL");
    r.push(0);
    match Lr::parse(tx::SYMLINK, &r, 0).unwrap() {
        Lr::Create { name, target, .. } => assert_eq!((name, target), (b"ln".to_vec(), Some(b"target".to_vec()))),
        other => panic!("{other:?}"),
    }
}
