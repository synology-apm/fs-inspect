use super::*;
use fs_inspect_core::ErrorKind;
use fs_inspect_testkit::regf::{HiveBuilder, ListKind};
use proptest::prelude::*;

fn names(keys: &[Key]) -> Vec<String> {
    keys.iter().map(|k| k.name().to_string()).collect()
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// The file offset of each allocated cell whose body starts with `sig`.
fn cells(hive: &[u8], sig: &[u8; 2]) -> Vec<usize> {
    (BASE_BLOCK..hive.len() - 8)
        .step_by(8)
        .filter(|&p| &hive[p + 4..p + 6] == sig && i32::from_le_bytes(hive[p..p + 4].try_into().unwrap()) < 0)
        .collect()
}

/// The file offset of the `nk` cell of key `name`.
fn nk(hive: &[u8], name: &str) -> usize {
    let h = Hive::open(hive).unwrap();
    let found = cells(hive, b"nk").into_iter().find(|&p| {
        let k = Key::read(h, (p - BASE_BLOCK) as u32).unwrap();
        k.name() == name
    });
    found.unwrap_or_else(|| panic!("no key {name}"))
}

/// Add a hive bin at the end with one allocated cell holding `body`; the cell's offset.
fn append_cell(hive: &mut Vec<u8>, body: &[u8]) -> u32 {
    let start = hive.len();
    let cell = (4 + body.len()).next_multiple_of(8);
    let size = (BIN_HEADER + cell).next_multiple_of(0x1000);
    hive.resize(start + size, 0);
    hive[start..start + 4].copy_from_slice(b"hbin");
    put32(hive, start + 4, (start - BASE_BLOCK) as u32);
    put32(hive, start + 8, size as u32);
    let at = start + BIN_HEADER;
    hive[at..at + 4].copy_from_slice(&(-(cell as i32)).to_le_bytes());
    hive[at + 4..at + 4 + body.len()].copy_from_slice(body);
    if at + cell < start + size {
        put32(hive, at + cell, (start + size - at - cell) as u32);
    }
    let data = (hive.len() - BASE_BLOCK) as u32;
    put32(hive, 0x28, data);
    (at - BASE_BLOCK) as u32
}

/// A subkey list cell.
fn list_cell(sig: &[u8; 2], offsets: &[u32]) -> Vec<u8> {
    let mut b = sig.to_vec();
    b.extend_from_slice(&(offsets.len() as u16).to_le_bytes());
    for o in offsets {
        b.extend_from_slice(&o.to_le_bytes());
        if matches!(sig, b"lf" | b"lh") {
            b.extend_from_slice(&[0; 4]);
        }
    }
    b
}

fn sample() -> Vec<u8> {
    HiveBuilder::new()
        .key("ControlSet001\\Control\\Session Manager")
        .value_sz("PendingFileRenameOperations", "x")
        .key("ControlSet001\\Services\\disk")
        .value_dword("Start", 0)
        .value_binary("Tiny", &[1, 2, 3])
        .value_binary("Four", &[1, 2, 3, 4])
        .value_binary("Five", &[1, 2, 3, 4, 5])
        .value_binary("Empty", &[])
        .value("", REG_SZ, b"d\0e\0f\0\0\0")
        .value("Q", REG_QWORD, &u64::MAX.to_le_bytes())
        .key("Select")
        .value_dword("Current", 1)
        .build()
}

#[test]
fn nested_keys_and_values_round_trip() {
    let bytes = sample();
    let hive = Hive::open(&bytes).unwrap();
    assert_eq!(hive.root().unwrap().name(), "ROOT");
    assert_eq!(names(&hive.root().unwrap().subkeys().unwrap()), ["ControlSet001", "Select"]);
    let disk = hive.key("ControlSet001\\Services\\disk").unwrap().unwrap();
    assert_eq!(disk.name(), "disk");
    assert!(disk.subkeys().unwrap().is_empty());
    let values = disk.values().unwrap();
    let got: Vec<(&str, u32, &[u8])> = values.iter().map(|v| (v.name.as_str(), v.kind, &v.data[..])).collect();
    assert_eq!(
        got,
        [
            ("Start", REG_DWORD, &[0, 0, 0, 0][..]),
            ("Tiny", REG_BINARY, &[1, 2, 3]),
            ("Four", REG_BINARY, &[1, 2, 3, 4]),
            ("Five", REG_BINARY, &[1, 2, 3, 4, 5]),
            ("Empty", REG_BINARY, &[]),
            ("", REG_SZ, b"d\0e\0f\0\0\0"),
            ("Q", REG_QWORD, &[0xFF; 8]),
        ]
    );
    assert_eq!(disk.value("start").unwrap().unwrap().data, [0, 0, 0, 0]);
    assert_eq!(disk.value("").unwrap().unwrap().kind, REG_SZ);
    assert!(disk.value("missing").unwrap().is_none());
    let sm = hive.key("\\ControlSet001\\Control\\Session Manager\\").unwrap().unwrap();
    assert_eq!(sm.values().unwrap()[0].data, b"x\0\0\0");
    assert!(hive.root().unwrap().values().unwrap().is_empty());
}

#[test]
fn lookup_ignores_case_and_misses_are_none() {
    let bytes = sample();
    let hive = Hive::open(&bytes).unwrap();
    for path in ["controlset001\\SERVICES\\Disk", "CONTROLSET001\\services\\DISK"] {
        assert_eq!(hive.key(path).unwrap().unwrap().name(), "disk", "{path}");
    }
    for path in ["", "\\", "\\\\"] {
        assert_eq!(hive.key(path).unwrap().unwrap().name(), "ROOT", "{path:?}");
    }
    assert!(hive.key("ControlSet002").unwrap().is_none());
    assert!(hive.key("ControlSet001\\Services\\disk\\Enum").unwrap().is_none());
    assert!(hive.key("Select\\Current").unwrap().is_none());
}

#[test]
fn every_subkey_list_kind_is_read() {
    let children = ["Delta", "alpha", "Charlie", "bravo", "Echo"];
    for kind in [ListKind::Lf, ListKind::Lh, ListKind::Li, ListKind::Ri] {
        let mut b = HiveBuilder::new().key("Parent").list_kind(kind);
        for c in children {
            b = b.key(&format!("Parent\\{c}")).value_sz("Name", c);
        }
        let bytes = b.build();
        let sig: &[u8; 2] = match kind {
            ListKind::Lf => b"lf",
            ListKind::Lh => b"lh",
            ListKind::Li => b"li",
            ListKind::Ri => b"ri",
        };
        assert!(!cells(&bytes, sig).is_empty(), "{kind:?}");
        let hive = Hive::open(&bytes).unwrap();
        let parent = hive.key("parent").unwrap().unwrap();
        // The writer sorts by upper-cased name, as Windows does.
        assert_eq!(names(&parent.subkeys().unwrap()), ["alpha", "bravo", "Charlie", "Delta", "Echo"], "{kind:?}");
        for c in children {
            let k = parent.subkey(&c.to_lowercase()).unwrap().unwrap();
            assert_eq!(k.name(), c);
            let expect: Vec<u8> = c.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
            assert_eq!(k.value("NAME").unwrap().unwrap().data, expect);
        }
    }
}

#[test]
fn byte_and_utf16_names() {
    let bytes = HiveBuilder::new()
        .key("Café")
        .value_dword("Größe", 1)
        .utf16_names()
        .key("Café\\Ünïcode✓")
        .value_dword("Ωmega", 2)
        .value_dword("plain", 3)
        .build();
    let hive = Hive::open(&bytes).unwrap();
    // One byte per character (Latin-1), matched without regard to case.
    let cafe = hive.key("CAFÉ").unwrap().unwrap();
    assert_eq!(cafe.name(), "Café");
    assert_eq!(cafe.value("GRÖßE").unwrap().unwrap().data, 1u32.to_le_bytes());
    let u = hive.key("café\\ÜNÏCODE✓").unwrap().unwrap();
    assert_eq!(u.name(), "Ünïcode✓");
    let values = u.values().unwrap();
    assert_eq!(values.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(), ["Ωmega", "plain"]);
    assert_eq!(u.value("ωMEGA").unwrap().unwrap().data, 2u32.to_le_bytes());
    // "plain" was stored as UTF-16: its name's bytes hold NULs.
    let vk = cells(&bytes, b"vk").into_iter().find(|&p| bytes[p + 24..].starts_with(b"p\0l\0")).unwrap();
    assert_eq!(le32(&bytes, vk + 4 + 16) & 1, 0);
}

#[test]
fn many_keys_span_several_bins() {
    let mut b = HiveBuilder::new();
    for i in 0..300 {
        b = b.key(&format!("K{i:03}")).value_binary("Data", &[i as u8; 100]);
    }
    let bytes = b.build();
    assert!(cells(&bytes, b"nk").len() > 300);
    assert!(bytes.len() > 8 * 0x1000);
    let hive = Hive::open(&bytes).unwrap();
    assert_eq!(hive.root().unwrap().subkeys().unwrap().len(), 300);
    assert_eq!(hive.key("k299").unwrap().unwrap().value("data").unwrap().unwrap().data, [43u8; 100]);
}

#[test]
fn a_prefix_opens_and_what_is_cut_off_is_an_error() {
    let mut b = HiveBuilder::new();
    for i in 0..100 {
        b = b.key(&format!("K{i:03}")).value_binary("Data", &[1; 200]);
    }
    let bytes = b.build();
    // The root key comes first, its subkey list (written after the keys) in the last bin.
    let last_bin = (BASE_BLOCK..bytes.len()).step_by(0x1000).rfind(|&p| &bytes[p..p + 4] == b"hbin").unwrap();
    assert!(last_bin > 0x2000);
    for len in [last_bin, last_bin + 16, last_bin + 0x800] {
        let hive = Hive::open(&bytes[..len]).unwrap();
        assert_eq!(hive.root().unwrap().name(), "ROOT");
        assert_eq!(hive.key("K000").unwrap_err().kind(), ErrorKind::Corrupt, "{len}");
    }
    let hive = Hive::open(&bytes).unwrap();
    assert_eq!(hive.root().unwrap().subkeys().unwrap().len(), 100);
}

#[test]
fn not_a_hive() {
    let bytes = sample();
    for short in [&bytes[..0], &bytes[..0x1000], &bytes[..0x101F]] {
        assert_eq!(Hive::open(short).unwrap_err().kind(), ErrorKind::Format);
    }
    let mut b = bytes.clone();
    b[0] = b'R';
    assert_eq!(Hive::open(&b).unwrap_err().kind(), ErrorKind::Format);
}

#[test]
fn damaged_base_block_and_bins() {
    let bytes = sample();
    let bad = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = bytes.clone();
        f(&mut b);
        Hive::open(&b).map(|_| ()).unwrap_err()
    };
    // Bin signature, offset and size.
    assert!(bad(&|b| b[0x1000] = b'H').to_string().contains("hbin"));
    assert_eq!(bad(&|b| put32(b, 0x1004, 0x1000)).kind(), ErrorKind::Corrupt);
    assert_eq!(bad(&|b| put32(b, 0x1008, 0)).kind(), ErrorKind::Corrupt);
    assert_eq!(bad(&|b| put32(b, 0x1008, 0x1001)).kind(), ErrorKind::Corrupt);
    // A first bin cut short by the data size.
    assert_eq!(bad(&|b| put32(b, 0x28, 16)).kind(), ErrorKind::Corrupt);
    // The root cell past the end, unaligned into a cell's middle, not a key.
    assert_eq!(bad(&|b| put32(b, 0x24, 0x7FFF_FFF0)).kind(), ErrorKind::Corrupt);
    assert_eq!(bad(&|b| put32(b, 0x24, u32::MAX)).kind(), ErrorKind::Corrupt);
    assert_eq!(bad(&|b| put32(b, 0x24, 0x22)).kind(), ErrorKind::Corrupt);
    let vk = (cells(&bytes, b"vk")[0] - BASE_BLOCK) as u32;
    assert!(bad(&|b| put32(b, 0x24, vk)).to_string().contains("not a key"));
}

#[test]
fn damaged_cells() {
    let bytes = sample();
    let root = le32(&bytes, 0x24) as usize + BASE_BLOCK;
    let open_root = |b: &[u8]| Hive::open(b).map(|_| ()).unwrap_err();
    for size in [0i32, 16, -4, i32::MIN, -0x7FFF_0000] {
        let mut b = bytes.clone();
        b[root..root + 4].copy_from_slice(&size.to_le_bytes());
        assert_eq!(open_root(&b).kind(), ErrorKind::Corrupt, "size {size}");
    }
    // A key name longer than its cell.
    let mut b = bytes.clone();
    b[root + 4 + 72..root + 4 + 74].copy_from_slice(&0xFFFFu16.to_le_bytes());
    assert!(open_root(&b).to_string().contains("name past its cell"));

    // The disk key's lists and values.
    let disk = nk(&bytes, "disk") + 4;
    let lookup =
        |b: &[u8]| -> Result<Vec<Value>> { Hive::open(b)?.key("ControlSet001\\Services\\disk")?.unwrap().values() };
    let mut b = bytes.clone();
    put32(&mut b, disk + 36, u32::MAX);
    assert!(lookup(&b).unwrap_err().to_string().contains("shorter than"));
    let mut b = bytes.clone();
    put32(&mut b, disk + 40, 0x10_0000);
    assert!(lookup(&b).unwrap_err().to_string().contains("past the end"));
    let services = nk(&bytes, "Services") + 4;
    let mut b = bytes.clone();
    put32(&mut b, services + 28, 0x7FFF_FFF8);
    assert_eq!(lookup(&b).unwrap_err().kind(), ErrorKind::Corrupt);
    // A subkey list pointing at a value.
    let mut b = bytes.clone();
    put32(&mut b, services + 28, (cells(&bytes, b"vk")[0] - BASE_BLOCK) as u32);
    assert!(lookup(&b).unwrap_err().to_string().contains("not a subkey list"));
    // A list count past its cell.
    let lh = le32(&bytes, services + 28) as usize + BASE_BLOCK + 4;
    let mut b = bytes.clone();
    b[lh + 2..lh + 4].copy_from_slice(&0xFFFFu16.to_le_bytes());
    assert!(lookup(&b).unwrap_err().to_string().contains("runs past its cell"));
    // A list entry that is not a key.
    let mut b = bytes.clone();
    put32(&mut b, lh + 4, le32(&bytes, services + 28));
    assert!(lookup(&b).unwrap_err().to_string().contains("not a key"));
}

#[test]
fn damaged_values() {
    let bytes = sample();
    let vk_named = |name: &str| {
        cells(&bytes, b"vk").into_iter().find(|&p| bytes[p + 24..].starts_with(name.as_bytes())).unwrap() + 4
    };
    let values =
        |b: &[u8]| -> Result<Vec<Value>> { Hive::open(b)?.key("ControlSet001\\Services\\disk")?.unwrap().values() };
    // Resident data longer than the offset field.
    let mut b = bytes.clone();
    put32(&mut b, vk_named("Tiny") + 4, 0x8000_0005);
    assert!(values(&b).unwrap_err().to_string().contains("offset field"));
    // Data longer than its cell, data past the end.
    let mut b = bytes.clone();
    put32(&mut b, vk_named("Five") + 4, 200);
    assert!(values(&b).unwrap_err().to_string().contains("smaller cell"));
    let mut b = bytes.clone();
    put32(&mut b, vk_named("Five") + 8, 0x0FFF_FFF0);
    assert_eq!(values(&b).unwrap_err().kind(), ErrorKind::Corrupt);
    // A name longer than its cell; a value list entry that is not a value.
    let mut b = bytes.clone();
    b[vk_named("Five") + 2..vk_named("Five") + 4].copy_from_slice(&0x7FFFu16.to_le_bytes());
    assert!(values(&b).unwrap_err().to_string().contains("name past its cell"));
    let mut b = bytes.clone();
    let disk = nk(&bytes, "disk") + 4;
    let list = le32(&bytes, disk + 40) as usize + BASE_BLOCK + 4;
    put32(&mut b, list, (nk(&bytes, "disk") - BASE_BLOCK) as u32);
    assert!(values(&b).unwrap_err().to_string().contains("not a value"));
}

#[test]
fn data_split_into_segments_is_refused() {
    // Data over 16344 bytes starting with "db" is a segment list.
    let mut big = b"db".to_vec();
    big.resize(20_000, 0);
    let bytes = HiveBuilder::new().key("K").value_binary("Big", &big).value_binary("Plain", &[9; 20_000]).build();
    let k = Hive::open(&bytes).unwrap().key("K").unwrap().unwrap();
    assert_eq!(k.values().unwrap_err().kind(), ErrorKind::Unsupported);
    // Without the signature, a large value in one cell is read.
    let bytes = HiveBuilder::new().key("K").value_binary("Plain", &[9; 20_000]).build();
    let k = Hive::open(&bytes).unwrap().key("K").unwrap().unwrap();
    assert_eq!(k.values().unwrap()[0].data, vec![9; 20_000]);
}

#[test]
fn ri_lists_nest_one_level_only() {
    let bytes = HiveBuilder::new().key("P").list_kind(ListKind::Ri).key("P\\A").key("P\\B").key("P\\C").build();
    let p = nk(&bytes, "P") + 4;
    let subkeys = |b: &[u8]| -> Result<Vec<String>> { Ok(names(&Hive::open(b)?.key("P")?.unwrap().subkeys()?)) };
    assert_eq!(subkeys(&bytes).unwrap(), ["A", "B", "C"]);
    // An ri list naming itself.
    let ri = le32(&bytes, p + 28);
    let mut b = bytes.clone();
    put32(&mut b, ri as usize + BASE_BLOCK + 4 + 4, ri);
    assert!(subkeys(&b).unwrap_err().to_string().contains("an ri list inside an ri list"));
    // An ri list naming another ri list.
    let mut b = bytes.clone();
    let outer = append_cell(&mut b, &list_cell(b"ri", &[ri]));
    put32(&mut b, p + 28, outer);
    assert!(subkeys(&b).unwrap_err().to_string().contains("an ri list inside an ri list"));
}

#[test]
fn subkey_lists_have_a_limit() {
    // 65535 entries of an ri list, each naming the same list of 17 keys: over a million.
    let mut b = HiveBuilder::new().key("P");
    for i in 0..17 {
        b = b.key(&format!("P\\K{i}"));
    }
    let mut bytes = b.build();
    let p = nk(&bytes, "P") + 4;
    let lh = le32(&bytes, p + 28);
    let ri = append_cell(&mut bytes, &list_cell(b"ri", &vec![lh; 0xFFFF]));
    put32(&mut bytes, p + 28, ri);
    let e = Hive::open(&bytes).unwrap().key("P").unwrap().unwrap().subkeys().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Limit);
    // The same through a short ri list is read.
    let ri = append_cell(&mut bytes, &list_cell(b"ri", &[lh, lh]));
    put32(&mut bytes, p + 28, ri);
    assert_eq!(Hive::open(&bytes).unwrap().key("P").unwrap().unwrap().subkeys().unwrap().len(), 34);
}

#[test]
fn a_key_listed_as_its_own_subkey_does_not_loop() {
    let mut bytes = HiveBuilder::new().key("A\\B").build();
    let a = nk(&bytes, "A") + 4;
    let list = le32(&bytes, a + 28) as usize + BASE_BLOCK + 4;
    put32(&mut bytes, list + 4, (a - 4 - BASE_BLOCK) as u32);
    let hive = Hive::open(&bytes).unwrap();
    assert_eq!(hive.key("A\\A\\A\\A").unwrap().unwrap().name(), "A");
    assert!(hive.key("A\\B").unwrap().is_none());
}

/// Read everything reachable from the root, a few levels deep.
fn walk(key: &Key, depth: u32) {
    let _ = key.values();
    if depth == 0 {
        return;
    }
    if let Ok(subs) = key.subkeys() {
        for k in subs.iter().take(64) {
            walk(k, depth - 1);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(256), ..ProptestConfig::default() })]

    #[test]
    fn mutated_hives_never_panic(muts in prop::collection::vec((any::<usize>(), any::<u8>()), 1..16), cut in any::<usize>()) {
        let mut bytes = HiveBuilder::new()
            .key("A").list_kind(ListKind::Ri)
            .key("A\\B").value_binary("V", &[1; 40]).value_dword("D", 7)
            .key("A\\C").list_kind(ListKind::Li)
            .key("A\\C\\D").utf16_names().value_sz("Name", "text")
            .key("A\\E").list_kind(ListKind::Lf)
            .key("MountedDevices").value_binary("\\DosDevices\\C:", &[0; 12])
            .build();
        for (at, v) in muts {
            // Mostly the hive bins, sometimes the base block.
            let i = if at % 8 == 0 { at % 0x40 } else { BASE_BLOCK + at % (bytes.len() - BASE_BLOCK) };
            bytes[i] = v;
        }
        let len = if cut % 4 == 0 { cut % (bytes.len() + 1) } else { bytes.len() };
        if let Ok(hive) = Hive::open(&bytes[..len]) {
            if let Ok(root) = hive.root() {
                walk(&root, 4);
            }
            let _ = hive.key("a\\c\\d");
            let _ = crate::mounted_devices::drive_letters(&hive);
        }
    }

    #[test]
    fn random_bytes_never_panic(body in prop::collection::vec(any::<u8>(), 0..0x2000), root in any::<u32>()) {
        let mut bytes = vec![0u8; BASE_BLOCK];
        bytes[..4].copy_from_slice(b"regf");
        put32(&mut bytes, 0x24, root % 0x2000);
        put32(&mut bytes, 0x28, 0x1000);
        let mut bin = vec![0u8; 0x1000];
        bin[..4].copy_from_slice(b"hbin");
        put32(&mut bin, 8, 0x1000);
        let n = body.len().min(0x1000 - BIN_HEADER);
        bin[BIN_HEADER..BIN_HEADER + n].copy_from_slice(&body[..n]);
        bytes.extend_from_slice(&bin);
        if let Ok(hive) = Hive::open(&bytes)
            && let Ok(root) = hive.root()
        {
            walk(&root, 3);
        }
    }
}
