//! A read-only reader of Windows registry hive files (`regf`), enough to look up keys by path
//! and read their values.
//!
//! # Layout
//!
//! A hive starts with a 4 KiB base block: the signature `regf`, the offset of the root key's cell
//! at 0x24 and the size of the hive bins data at 0x28. The hive bins follow from byte 0x1000.
//! Each bin starts with a 32-byte header (`hbin`, its offset from the first bin, its size, a
//! multiple of 4 KiB) and holds cells. Cell offsets count from the first bin.
//!
//! A cell starts with its size as an `i32`: negative when the cell is allocated, positive when it
//! is free. The cells used here:
//!
//! - `nk`, a key: subkey count at 20, subkey list at 28, value count at 36, value list at 40,
//!   name length at 72, the name at 76. Flag 0x20 at 2 means the name has one byte per
//!   character; otherwise it is UTF-16LE.
//! - `lf` and `lh` (pairs of key offset and name hash), `li` (key offsets): the subkey lists, a
//!   16-bit count at 2 and the entries from 4. `ri` lists such lists.
//! - A value list: a cell of `u32` offsets of `vk` cells, as many as the key's value count.
//! - `vk`, a value: name length at 2, data size at 4, data offset at 8, type at 12, flags at 16
//!   (0x1: one byte per character in the name), the name at 20. When the size's high bit is set,
//!   the data (at most 4 bytes) is the offset field itself. Data over 16344 bytes may be split
//!   into segments by a `db` cell; this reader refuses those.
//!
//! Every offset and length is checked against the hive bins, and counts are bounded by the cells
//! that hold them, so a damaged hive gives an error, never a panic or an unbounded allocation.
//! The base block's checksum and sequence numbers are not checked: a hive copied from a running
//! system may be dirty and still readable.

use fs_inspect_core::bytes::{slice, u16_at, u32_at};
use fs_inspect_core::{Error, Result};

const BASE_BLOCK: usize = 0x1000;
const BIN_HEADER: usize = 32;
const BIN_ALIGN: u32 = 0x1000;
const NAME_IS_BYTES_KEY: u16 = 0x20;
const NAME_IS_BYTES_VALUE: u16 = 0x1;
const DATA_RESIDENT: u32 = 0x8000_0000;
/// The largest value data kept in one cell; past it, data may be split by a `db` cell.
const MAX_SINGLE_CELL_DATA: u32 = 16344;
/// The most subkeys one key may list (an `ri` list can name the same list many times).
const MAX_SUBKEYS: usize = 1 << 20;

fn corrupt(msg: impl std::fmt::Display) -> Error {
    Error::corrupt(format_args!("registry hive: {msg}"))
}

/// A hive in memory: the caller's bytes, borrowed.
#[derive(Debug, Clone, Copy)]
pub struct Hive<'a> {
    bytes: &'a [u8],
    /// The end of the hive bins that lie inside `bytes`.
    end: usize,
    root: u32,
}

impl<'a> Hive<'a> {
    /// Check the base block and the hive bins' headers. `bytes` may stop short of the hive's
    /// full size (a prefix of the file): the bins present are read, and cells past the end are
    /// errors when they are reached.
    pub fn open(bytes: &'a [u8]) -> Result<Hive<'a>> {
        if bytes.len() < BASE_BLOCK + BIN_HEADER {
            return Err(Error::format("registry hive: shorter than its base block and first bin"));
        }
        if &bytes[..4] != b"regf" {
            return Err(Error::format("registry hive: no regf signature"));
        }
        let root = u32_at(bytes, 0x24)?;
        let data_size = u32_at(bytes, 0x28)? as usize;
        let mut end = BASE_BLOCK.saturating_add(data_size).min(bytes.len());
        let mut at = BASE_BLOCK;
        while at < end {
            let header = match slice(bytes, at, BIN_HEADER) {
                Ok(h) if at + BIN_HEADER <= end => h,
                // A partial bin header at the end of what was read.
                _ if at > BASE_BLOCK => {
                    end = at;
                    break;
                }
                _ => return Err(corrupt("the first hive bin is cut short")),
            };
            if &header[..4] != b"hbin" {
                return Err(corrupt(format_args!("no hbin signature at {at:#x}")));
            }
            let offset = u32_at(header, 4)? as usize;
            let size = u32_at(header, 8)?;
            if offset != at - BASE_BLOCK {
                return Err(corrupt(format_args!("the hive bin at {at:#x} says it is at {offset:#x}")));
            }
            if size == 0 || size % BIN_ALIGN != 0 {
                return Err(corrupt(format_args!("the hive bin at {at:#x} has size {size:#x}")));
            }
            at = at.saturating_add(size as usize);
        }
        let hive = Hive { bytes, end, root };
        hive.root()?;
        Ok(hive)
    }

    /// The root key.
    pub fn root(&self) -> Result<Key<'a>> {
        Key::read(*self, self.root)
    }

    /// The key at `path` below the root: names separated by `\`, matched without regard to
    /// case (each character upper-cased on its own). Empty components are skipped, so `""` and
    /// `"\"` are the root. `None` when a key on the way does not exist.
    pub fn key(&self, path: &str) -> Result<Option<Key<'a>>> {
        let mut key = self.root()?;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            match key.subkey(part)? {
                Some(k) => key = k,
                None => return Ok(None),
            }
        }
        Ok(Some(key))
    }

    /// The body of the allocated cell at `offset` (without its size field).
    fn cell(&self, offset: u32) -> Result<&'a [u8]> {
        let bad = |what: &str| corrupt(format_args!("cell {offset:#x}: {what}"));
        let at = BASE_BLOCK.checked_add(offset as usize).filter(|&a| a.saturating_add(4) <= self.end);
        let at = at.ok_or_else(|| bad("past the end of the hive bins"))?;
        let size = i32::from_le_bytes([self.bytes[at], self.bytes[at + 1], self.bytes[at + 2], self.bytes[at + 3]]);
        if size >= 0 {
            return Err(bad("not allocated"));
        }
        let len = size.unsigned_abs() as usize;
        if len < 8 {
            return Err(bad("too small"));
        }
        if at.saturating_add(len) > self.end {
            return Err(bad("runs past the end of the hive bins"));
        }
        Ok(&self.bytes[at + 4..at + len])
    }
}

/// One key of a [`Hive`].
#[derive(Debug, Clone)]
pub struct Key<'a> {
    hive: Hive<'a>,
    name: String,
    subkey_count: u32,
    subkey_list: u32,
    value_count: u32,
    value_list: u32,
}

impl<'a> Key<'a> {
    fn read(hive: Hive<'a>, offset: u32) -> Result<Key<'a>> {
        let c = hive.cell(offset)?;
        if c.len() < 76 || &c[..2] != b"nk" {
            return Err(corrupt(format_args!("cell {offset:#x} is not a key")));
        }
        let flags = u16_at(c, 2)?;
        let name_len = u16_at(c, 72)? as usize;
        let raw = slice(c, 76, name_len).map_err(|_| corrupt(format_args!("key {offset:#x}: name past its cell")))?;
        Ok(Key {
            hive,
            name: decode_name(raw, flags & NAME_IS_BYTES_KEY != 0),
            subkey_count: u32_at(c, 20)?,
            subkey_list: u32_at(c, 28)?,
            value_count: u32_at(c, 36)?,
            value_list: u32_at(c, 40)?,
        })
    }

    /// The key's name, as stored.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The subkeys, in the order of the key's list (sorted by upper-cased name in a hive
    /// Windows wrote).
    pub fn subkeys(&self) -> Result<Vec<Key<'a>>> {
        let mut offsets = Vec::new();
        if self.subkey_count != 0 {
            self.list_offsets(self.subkey_list, true, &mut offsets)?;
        }
        offsets.into_iter().map(|o| Key::read(self.hive, o)).collect()
    }

    /// The subkey named `name` (without regard to case).
    pub fn subkey(&self, name: &str) -> Result<Option<Key<'a>>> {
        Ok(self.subkeys()?.into_iter().find(|k| same_name(&k.name, name)))
    }

    /// The key offsets of the subkey list at `offset`. `ri` lists only at the top.
    fn list_offsets(&self, offset: u32, top: bool, out: &mut Vec<u32>) -> Result<()> {
        let c = self.hive.cell(offset)?;
        let sig = c.get(..2).ok_or_else(|| corrupt("subkey list too small"))?;
        let count = u16_at(c, 2)? as usize;
        let stride = match sig {
            b"lf" | b"lh" => 8,
            b"li" | b"ri" => 4,
            _ => return Err(corrupt(format_args!("cell {offset:#x} is not a subkey list"))),
        };
        let entries = slice(c, 4, count * stride)
            .map_err(|_| corrupt(format_args!("subkey list {offset:#x} runs past its cell")))?;
        for e in entries.chunks_exact(stride) {
            let o = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
            if sig == b"ri" {
                if !top {
                    return Err(corrupt(format_args!("subkey list {offset:#x}: an ri list inside an ri list")));
                }
                self.list_offsets(o, false, out)?;
            } else {
                if out.len() >= MAX_SUBKEYS {
                    return Err(Error::limit(format_args!(
                        "registry hive: more than {MAX_SUBKEYS} subkeys in one key"
                    )));
                }
                out.push(o);
            }
        }
        Ok(())
    }

    /// The values, in the order of the key's value list.
    pub fn values(&self) -> Result<Vec<Value>> {
        if self.value_count == 0 {
            return Ok(Vec::new());
        }
        let c = self.hive.cell(self.value_list)?;
        let list = (self.value_count as usize).checked_mul(4).and_then(|n| c.get(..n)).ok_or_else(|| {
            corrupt(format_args!("value list {:#x} shorter than its {} values", self.value_list, self.value_count))
        })?;
        list.as_chunks::<4>().0.iter().map(|e| self.value_at(u32::from_le_bytes(*e))).collect()
    }

    /// The value named `name` (without regard to case; `""` is the key's default value).
    pub fn value(&self, name: &str) -> Result<Option<Value>> {
        Ok(self.values()?.into_iter().find(|v| same_name(&v.name, name)))
    }

    fn value_at(&self, offset: u32) -> Result<Value> {
        let c = self.hive.cell(offset)?;
        if c.len() < 20 || &c[..2] != b"vk" {
            return Err(corrupt(format_args!("cell {offset:#x} is not a value")));
        }
        let name_len = u16_at(c, 2)? as usize;
        let size = u32_at(c, 4)?;
        let data_offset = u32_at(c, 8)?;
        let kind = u32_at(c, 12)?;
        let flags = u16_at(c, 16)?;
        let raw = slice(c, 20, name_len).map_err(|_| corrupt(format_args!("value {offset:#x}: name past its cell")))?;
        let name = decode_name(raw, flags & NAME_IS_BYTES_VALUE != 0);
        let data = if size & DATA_RESIDENT != 0 {
            let len = (size & !DATA_RESIDENT) as usize;
            if len > 4 {
                return Err(corrupt(format_args!("value {offset:#x}: {len} bytes kept in the offset field")));
            }
            data_offset.to_le_bytes()[..len].to_vec()
        } else if size == 0 {
            Vec::new()
        } else {
            let d = self.hive.cell(data_offset)?;
            if size > MAX_SINGLE_CELL_DATA && d.starts_with(b"db") {
                return Err(Error::unsupported(format_args!("registry hive: value {name:?} split into segments (db)")));
            }
            d.get(..size as usize)
                .ok_or_else(|| corrupt(format_args!("value {offset:#x}: {size} bytes of data in a smaller cell")))?
                .to_vec()
        };
        Ok(Value { name, kind, data })
    }
}

/// A value of a [`Key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// The name; empty for the key's default value.
    pub name: String,
    /// The type (`REG_*`: 1 `REG_SZ`, 3 `REG_BINARY`, 4 `REG_DWORD`, ...).
    pub kind: u32,
    pub data: Vec<u8>,
}

/// `REG_SZ`.
pub const REG_SZ: u32 = 1;
/// `REG_EXPAND_SZ`.
pub const REG_EXPAND_SZ: u32 = 2;
/// `REG_BINARY`.
pub const REG_BINARY: u32 = 3;
/// `REG_DWORD`.
pub const REG_DWORD: u32 = 4;
/// `REG_MULTI_SZ`.
pub const REG_MULTI_SZ: u32 = 7;
/// `REG_QWORD`.
pub const REG_QWORD: u32 = 11;

/// A name stored with one byte per character (Latin-1), or as UTF-16LE.
fn decode_name(raw: &[u8], bytes: bool) -> String {
    if bytes {
        raw.iter().map(|&b| char::from(b)).collect()
    } else {
        let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16_lossy(&units)
    }
}

/// Registry names compare without regard to case: character by character, each upper-cased when
/// its upper case is one character.
fn same_name(a: &str, b: &str) -> bool {
    a.chars().map(upper).eq(b.chars().map(upper))
}

fn upper(c: char) -> char {
    let mut u = c.to_uppercase();
    match (u.next(), u.next()) {
        (Some(x), None) => x,
        _ => c,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
