//! The volumes of the checkpoint [`ApfsFs`] uses (its superblock gives the object map and the
//! volume list): the container object map and every volume superblock.

use crate::ApfsFs;
use crate::format::btree::{Reader, Resolve};
use crate::format::layout::NX_MAX_FILE_SYSTEMS;
use crate::format::omap::{Omap, Virtual};
use crate::format::records::{ApfsSuperblock, OBJECT_TYPE_FS};
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::{Error, Result};

/// A volume superblock, as of the checkpoint in use.
#[derive(Debug, Clone)]
#[cfg_attr(not(any(test, feature = "change")), allow(dead_code, reason = "read by change tracking (`track`)"))]
pub struct Volume {
    /// Index in `nx_fs_oid[]`.
    pub index: usize,
    pub oid: u64,
    /// Transaction of the volume superblock.
    pub xid: u64,
    pub sb: ApfsSuperblock,
}

/// A slot of `nx_fs_oid[]` that is in use.
#[derive(Debug, Clone)]
#[cfg_attr(not(any(test, feature = "change")), allow(dead_code, reason = "read by change tracking (`track`)"))]
pub enum Slot {
    Ok(Box<Volume>),
    /// The superblock could not be read: the volume's files are not reported (its blocks are
    /// dirty).
    Bad {
        index: usize,
        oid: u64,
        error: Error,
    },
}

/// The container object map and the volumes of the checkpoint in use.
#[derive(Debug, Clone)]
#[cfg_attr(not(any(test, feature = "change")), allow(dead_code, reason = "read by change tracking (`track`)"))]
pub struct Container {
    pub reader: Reader,
    pub uuid: [u8; 16],
    /// Transaction of the checkpoint in use.
    pub xid: u64,
    /// `nx_next_xid` of that checkpoint.
    pub next_xid: u64,
    pub omap: std::sync::Arc<Omap>,
    pub slots: Vec<Slot>,
}

impl Container {
    /// The object map and volume superblocks of the checkpoint `fs` uses, read with `fs`'s
    /// source and limits.
    pub fn open(fs: &ApfsFs) -> Result<Self> {
        Self::open_logged(fs, crate::format::btree::ObjectLog::default())
    }

    /// [`Container::open`], logging the objects read (now and by later walks) to `log` while it
    /// records.
    pub fn open_logged(fs: &ApfsFs, log: crate::format::btree::ObjectLog) -> Result<Self> {
        let geo = fs.geometry();
        let reader = Reader {
            blocks: geo.reader(fs.source())?,
            geo,
            limits: fs.limits().clone(),
            log,
            integrity: fs.integrity.clone(),
            omaps: fs.omaps.clone(),
            nodes: None,
        };
        let sb = fs.superblock();
        let xid = sb.hdr.xid;
        let omap = reader.omap(sb.omap_oid, xid, StructureKind::ApfsContainerObjectMap)?;
        let res = Virtual { omap: &omap, block_size: reader.geo.block_size, seal: None };
        let n = (sb.max_file_systems as usize).clamp(1, NX_MAX_FILE_SYSTEMS);
        let mut slots = Vec::new();
        for (index, &oid) in sb.fs_oids.iter().enumerate().take(n) {
            if oid == 0 {
                continue;
            }
            let r = (|| -> Result<Volume> {
                let paddr = res.resolve(oid)?;
                let (h, b) = reader.read_obj(paddr, oid, OBJECT_TYPE_FS, StructureKind::ApfsVolumeSuperblock)?;
                let sb = ApfsSuperblock::parse(&b)?;
                if h.xid > xid {
                    return Err(Error::corrupt(format!("volume superblock xid {} after checkpoint {xid}", h.xid)));
                }
                Ok(Volume { index, oid, xid: h.xid, sb })
            })();
            match r {
                Ok(v) => slots.push(Slot::Ok(Box::new(v))),
                Err(e) => {
                    if e.scope() != Scope::Unit {
                        return Err(e);
                    }
                    slots.push(Slot::Bad { index, oid, error: e });
                }
            }
        }
        let (uuid, next_xid) = (sb.uuid, sb.next_xid);
        Ok(Container { reader, uuid, xid, next_xid, omap, slots })
    }
}
