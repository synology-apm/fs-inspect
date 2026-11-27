//! Windows registry hives for tests, written from the `regf` layout independently of the reader
//! in fs-inspect-guest: a base block, hive bins of 4 KiB (larger for a cell that needs it), `nk`
//! keys with `lf`, `lh`, `li` or `ri` subkey lists, `vk` values and their data cells. And the
//! data of `MountedDevices` values.
//!
//! ```
//! use fs_inspect_testkit::regf::{HiveBuilder, mbr_value};
//! let hive = HiveBuilder::new()
//!     .key("MountedDevices")
//!     .value_binary("\\DosDevices\\C:", &mbr_value(0x1234_5678, 1 << 20))
//!     .build();
//! assert_eq!(&hive[..4], b"regf");
//! ```

use fs_inspect_core::bytes::{put_u16, put_u32};

const BIN: usize = 0x1000;
const BIN_HEADER: usize = 32;
const NONE: u32 = u32::MAX;

/// The kind of list a key keeps its subkeys in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    /// Offsets and the first four characters of each name.
    Lf,
    /// Offsets and a hash of each name (what current Windows writes).
    Lh,
    /// Offsets only.
    Li,
    /// A list of `lh` lists, two subkeys in each.
    Ri,
}

#[derive(Debug, Clone)]
struct Node {
    name: String,
    utf16: bool,
    list: ListKind,
    children: Vec<Node>,
    values: Vec<Val>,
}

#[derive(Debug, Clone)]
struct Val {
    name: String,
    utf16: bool,
    kind: u32,
    data: Vec<u8>,
}

impl Node {
    fn new(name: &str, utf16: bool) -> Node {
        Node { name: name.to_string(), utf16, list: ListKind::Lh, children: Vec::new(), values: Vec::new() }
    }
}

/// A hive under construction. [`key`](Self::key) selects a key (creating it and the keys on the
/// way); the `value*` calls add values to the selected key.
#[derive(Debug, Clone)]
pub struct HiveBuilder {
    root: Node,
    /// The selected key, as child indices from the root.
    current: Vec<usize>,
    utf16: bool,
}

impl Default for HiveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HiveBuilder {
    /// An empty hive whose root key is named `ROOT`; the root is selected.
    pub fn new() -> Self {
        HiveBuilder { root: Node::new("ROOT", false), current: Vec::new(), utf16: false }
    }

    /// Store the names of the keys and values added from here on as UTF-16 (by default, names
    /// whose characters all fit a byte are stored one byte per character).
    pub fn utf16_names(mut self) -> Self {
        self.utf16 = true;
        self
    }

    /// Select the key at `path` (`\`-separated, from the root; `""` is the root), creating the
    /// keys missing on the way. An existing key matches without regard to case.
    pub fn key(mut self, path: &str) -> Self {
        let mut current = Vec::new();
        let mut node = &mut self.root;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            let i = match node.children.iter().position(|c| upper(&c.name) == upper(part)) {
                Some(i) => i,
                None => {
                    node.children.push(Node::new(part, self.utf16));
                    node.children.len() - 1
                }
            };
            current.push(i);
            node = &mut node.children[i];
        }
        self.current = current;
        self
    }

    /// Keep the selected key's subkeys in a list of `kind` (`lh` by default).
    pub fn list_kind(mut self, kind: ListKind) -> Self {
        self.selected().list = kind;
        self
    }

    /// Add a value of type `kind` (a `REG_*` number) to the selected key.
    pub fn value(mut self, name: &str, kind: u32, data: &[u8]) -> Self {
        let utf16 = self.utf16;
        self.selected().values.push(Val { name: name.to_string(), utf16, kind, data: data.to_vec() });
        self
    }

    /// A `REG_BINARY` value.
    pub fn value_binary(self, name: &str, data: &[u8]) -> Self {
        self.value(name, 3, data)
    }

    /// A `REG_SZ` value: UTF-16LE with its terminating NUL.
    pub fn value_sz(self, name: &str, text: &str) -> Self {
        let data: Vec<u8> = text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
        self.value(name, 1, &data)
    }

    /// A `REG_DWORD` value.
    pub fn value_dword(self, name: &str, v: u32) -> Self {
        self.value(name, 4, &v.to_le_bytes())
    }

    fn selected(&mut self) -> &mut Node {
        let mut node = &mut self.root;
        for &i in &self.current {
            node = &mut node.children[i];
        }
        node
    }

    /// The hive file.
    pub fn build(&self) -> Vec<u8> {
        let mut w = Writer { data: Vec::new(), bin_end: 0 };
        let root = w.key(&self.root, NONE, true);
        w.close_bin();
        let mut out = vec![0u8; BIN];
        out[..4].copy_from_slice(b"regf");
        put_u32(&mut out, 4, 1); // primary sequence number
        put_u32(&mut out, 8, 1); // secondary sequence number
        put_u32(&mut out, 0x14, 1); // major version
        put_u32(&mut out, 0x18, 5); // minor version
        put_u32(&mut out, 0x1C, 0); // primary file
        put_u32(&mut out, 0x20, 1); // direct memory load
        put_u32(&mut out, 0x24, root);
        put_u32(&mut out, 0x28, u32::try_from(w.data.len()).unwrap());
        put_u32(&mut out, 0x2C, 1); // clustering factor
        let sum = out[..0x1FC].as_chunks::<4>().0.iter().fold(0u32, |a, c| a ^ u32::from_le_bytes(*c));
        put_u32(&mut out, 0x1FC, sum);
        out.extend_from_slice(&w.data);
        out
    }
}

/// The hive bins being written: cells go into the current bin, and a new bin starts when one
/// does not fit (the rest of the old one becomes a free cell).
struct Writer {
    data: Vec<u8>,
    bin_end: usize,
}

impl Writer {
    /// An allocated cell with room for `body` bytes; its offset.
    fn alloc(&mut self, body: usize) -> u32 {
        let len = (4 + body).next_multiple_of(8);
        if self.data.len() + len > self.bin_end {
            self.close_bin();
            let start = self.data.len();
            let size = (BIN_HEADER + len).next_multiple_of(BIN);
            self.data.resize(start + BIN_HEADER, 0);
            self.data[start..start + 4].copy_from_slice(b"hbin");
            put_u32(&mut self.data, start + 4, u32::try_from(start).unwrap());
            put_u32(&mut self.data, start + 8, u32::try_from(size).unwrap());
            self.bin_end = start + size;
        }
        let at = self.data.len();
        self.data.resize(at + len, 0);
        self.data[at..at + 4].copy_from_slice(&(-i32::try_from(len).unwrap()).to_le_bytes());
        u32::try_from(at).unwrap()
    }

    /// Fill the rest of the current bin with a free cell.
    fn close_bin(&mut self) {
        let at = self.data.len();
        if at < self.bin_end {
            self.data.resize(self.bin_end, 0);
            put_u32(&mut self.data, at, u32::try_from(self.bin_end - at).unwrap());
        }
    }

    /// The body of the cell at `offset` (after its size).
    fn body(&mut self, offset: u32, len: usize) -> &mut [u8] {
        let at = offset as usize + 4;
        &mut self.data[at..at + len]
    }

    fn key(&mut self, node: &Node, parent: u32, root: bool) -> u32 {
        let (name, compressed) = encode_name(&node.name, node.utf16);
        let off = self.alloc(76 + name.len());
        let mut children: Vec<&Node> = node.children.iter().collect();
        children.sort_by_key(|c| upper(&c.name));
        let entries: Vec<(u32, &str)> = children.iter().map(|c| (self.key(c, off, false), c.name.as_str())).collect();
        let list = self.list(node.list, &entries);
        let mut vks = Vec::new();
        for v in &node.values {
            vks.push(self.value(v));
        }
        let value_list = if vks.is_empty() {
            NONE
        } else {
            let l = self.alloc(4 * vks.len());
            for (i, vk) in vks.iter().enumerate() {
                put_u32(self.body(l, 4 * vks.len()), 4 * i, *vk);
            }
            l
        };
        let max_name = children.iter().map(|c| c.name.encode_utf16().count() * 2).max().unwrap_or(0);
        let max_value_name = node.values.iter().map(|v| v.name.encode_utf16().count() * 2).max().unwrap_or(0);
        let max_data = node.values.iter().map(|v| v.data.len()).max().unwrap_or(0);
        let b = self.body(off, 76 + name.len());
        b[..2].copy_from_slice(b"nk");
        let flags = if compressed { 0x20 } else { 0 } | if root { 0x0C } else { 0 };
        put_u16(b, 2, flags);
        put_u32(b, 16, parent);
        put_u32(b, 20, u32::try_from(entries.len()).unwrap());
        put_u32(b, 28, list);
        put_u32(b, 32, NONE);
        put_u32(b, 36, u32::try_from(vks.len()).unwrap());
        put_u32(b, 40, value_list);
        put_u32(b, 44, NONE); // security
        put_u32(b, 48, NONE); // class name
        put_u32(b, 52, u32::try_from(max_name).unwrap());
        put_u32(b, 60, u32::try_from(max_value_name).unwrap());
        put_u32(b, 64, u32::try_from(max_data).unwrap());
        put_u16(b, 72, u16::try_from(name.len()).unwrap());
        b[76..].copy_from_slice(&name);
        off
    }

    fn list(&mut self, kind: ListKind, entries: &[(u32, &str)]) -> u32 {
        if entries.is_empty() {
            return NONE;
        }
        if kind == ListKind::Ri {
            let lists: Vec<u32> = entries.chunks(2).map(|c| self.list(ListKind::Lh, c)).collect();
            return self.simple_list(b"ri", lists.iter().map(|&o| (o, [0u8; 4])).collect());
        }
        let sig = match kind {
            ListKind::Lf => b"lf",
            ListKind::Lh => b"lh",
            _ => b"li",
        };
        let items = entries
            .iter()
            .map(|&(o, name)| {
                let hint = match kind {
                    ListKind::Lh => lh_hash(name).to_le_bytes(),
                    _ => {
                        let mut h = [0u8; 4];
                        for (slot, c) in h.iter_mut().zip(name.chars()) {
                            *slot = u8::try_from(u32::from(c)).unwrap_or(0);
                        }
                        h
                    }
                };
                (o, hint)
            })
            .collect();
        self.simple_list(sig, items)
    }

    /// A list cell: signature, count, then each offset (and its hint, in `lf` and `lh`).
    fn simple_list(&mut self, sig: &[u8; 2], items: Vec<(u32, [u8; 4])>) -> u32 {
        let stride = if matches!(sig, b"lf" | b"lh") { 8 } else { 4 };
        let len = 4 + stride * items.len();
        let off = self.alloc(len);
        let b = self.body(off, len);
        b[..2].copy_from_slice(sig);
        put_u16(b, 2, u16::try_from(items.len()).unwrap());
        for (i, (o, hint)) in items.iter().enumerate() {
            put_u32(b, 4 + stride * i, *o);
            if stride == 8 {
                b[8 + stride * i..12 + stride * i].copy_from_slice(hint);
            }
        }
        off
    }

    fn value(&mut self, v: &Val) -> u32 {
        let (name, compressed) = encode_name(&v.name, v.utf16);
        let len = u32::try_from(v.data.len()).unwrap();
        let (size, data) = if v.data.len() <= 4 {
            let mut d = [0u8; 4];
            d[..v.data.len()].copy_from_slice(&v.data);
            (len | 0x8000_0000, u32::from_le_bytes(d))
        } else {
            let d = self.alloc(v.data.len());
            self.body(d, v.data.len()).copy_from_slice(&v.data);
            (len, d)
        };
        let off = self.alloc(20 + name.len());
        let b = self.body(off, 20 + name.len());
        b[..2].copy_from_slice(b"vk");
        put_u16(b, 2, u16::try_from(name.len()).unwrap());
        put_u32(b, 4, size);
        put_u32(b, 8, data);
        put_u32(b, 12, v.kind);
        put_u16(b, 16, u16::from(compressed));
        b[20..].copy_from_slice(&name);
        off
    }
}

/// A name's bytes: one per character when `utf16` is not asked and every character fits a byte
/// (the second value is then true), else UTF-16LE.
fn encode_name(name: &str, utf16: bool) -> (Vec<u8>, bool) {
    if !utf16 && let Some(bytes) = name.chars().map(|c| u8::try_from(u32::from(c)).ok()).collect::<Option<Vec<u8>>>() {
        return (bytes, true);
    }
    (name.encode_utf16().flat_map(u16::to_le_bytes).collect(), false)
}

/// `s` upper-cased character by character (a character whose upper case is longer is kept).
fn upper(s: &str) -> String {
    s.chars()
        .map(|c| {
            let mut u = c.to_uppercase();
            match (u.next(), u.next()) {
                (Some(x), None) => x,
                _ => c,
            }
        })
        .collect()
}

/// The name hash of an `lh` entry: over the upper-cased name's UTF-16 units, `h = h * 37 + unit`.
pub fn lh_hash(name: &str) -> u32 {
    upper(name).encode_utf16().fold(0u32, |h, u| h.wrapping_mul(37).wrapping_add(u32::from(u)))
}

/// The data of a `MountedDevices` value for a partition of an MBR disk: the disk signature and
/// the partition's byte offset.
pub fn mbr_value(signature: u32, offset: u64) -> Vec<u8> {
    let mut v = signature.to_le_bytes().to_vec();
    v.extend_from_slice(&offset.to_le_bytes());
    v
}

/// The data of a `MountedDevices` value for a GPT partition (or an LDM volume): `DMIO:ID:` and
/// the GUID `guid` (`xxxxxxxx-xxxx-...`) in its binary, mixed-endian form.
pub fn gpt_value(guid: &str) -> Vec<u8> {
    let mut v = b"DMIO:ID:".to_vec();
    v.extend_from_slice(&fs_inspect_core::guid::parse(guid).expect("a GUID"));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bins_are_4k_and_cells_stay_inside_them() {
        let mut b = HiveBuilder::new().key("Big");
        for i in 0..200 {
            b = b.value_binary(&format!("v{i}"), &[i as u8; 40]);
        }
        let hive = b.value_binary("huge", &vec![7; 10_000]).build();
        assert_eq!(&hive[..4], b"regf");
        let data = u32::from_le_bytes(hive[0x28..0x2C].try_into().unwrap()) as usize;
        assert_eq!(hive.len(), BIN + data);
        let mut at = BIN;
        let mut bins = 0;
        while at < hive.len() {
            assert_eq!(&hive[at..at + 4], b"hbin");
            assert_eq!(u32::from_le_bytes(hive[at + 4..at + 8].try_into().unwrap()) as usize, at - BIN);
            let size = u32::from_le_bytes(hive[at + 8..at + 12].try_into().unwrap()) as usize;
            assert_eq!(size % BIN, 0);
            // The cells fill the bin exactly.
            let mut c = at + BIN_HEADER;
            while c < at + size {
                let len = i32::from_le_bytes(hive[c..c + 4].try_into().unwrap()).unsigned_abs() as usize;
                assert!(len >= 8 && len.is_multiple_of(8));
                c += len;
            }
            assert_eq!(c, at + size);
            at += size;
            bins += 1;
        }
        assert!(bins > 2, "{bins}");
        assert_eq!(at, hive.len());
    }

    #[test]
    fn hashes_and_value_data() {
        assert_eq!(lh_hash("a"), u32::from(b'A'));
        assert_eq!(lh_hash("ab"), u32::from(b'A') * 37 + u32::from(b'B'));
        assert_eq!(mbr_value(1, 2), [1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]);
        let g = gpt_value("00112233-4455-6677-8899-AABBCCDDEEFF");
        assert_eq!(&g[..8], b"DMIO:ID:");
        assert_eq!(
            &g[8..],
            &[0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        );
    }
}
