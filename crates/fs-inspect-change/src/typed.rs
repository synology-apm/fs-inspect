//! [`TypedScanner`]: a driver whose `FS_STATE` is a typed value. The engine versions it,
//! decodes it, and breaks continuity on one it cannot use, so drivers only compare states.

use crate::error::Result;
use crate::model::{Degrade, DegradeCode, FileState};
use crate::scanner::{Continuity, DriverExtra, FsScanner, Identity, PrevState, ScanContext, ScanSession};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// A file-system driver with a typed state. Every `TypedScanner` is an [`FsScanner`]: its
/// state is stored as `{"version": STATE_VERSION, "state": ...}`, and a previous state that
/// does not decode, or has another version, breaks continuity with [`STATE_CODE`](Self::STATE_CODE).
pub trait TypedScanner: Send + Sync + std::fmt::Debug {
    /// What the next scan compares against (journal position, generation, transaction id...).
    type State: Serialize + DeserializeOwned;
    /// Changed whenever `State` changes: a state of another version is not used.
    const STATE_VERSION: u32;
    /// The degrade code of a previous state that cannot be used (`<fs>-state`).
    const STATE_CODE: DegradeCode;

    /// [`FsScanner::identity`].
    fn identity(&self) -> Identity;

    /// The state of the current snapshot as the scan begins (taken once per scan). The scan
    /// may complete it (`scan_files` gets it mutably); what it holds at the end is stored for
    /// the next scan.
    fn current(&self) -> Result<Self::State>;

    /// Check the previous snapshot's state against the current one; `offline`:
    /// [`PrevState::offline`]. Default: `Ok`.
    fn continuity(&self, prev: &Self::State, cur: &Self::State, offline: bool) -> Continuity {
        let _ = (prev, cur, offline);
        Continuity::Ok
    }

    /// [`ScanSession::scan_files`], with the previous state when there is a usable previous
    /// snapshot (`None`: the first scan, or one whose continuity broke) and the current one.
    fn scan_files(
        &self,
        cx: &ScanContext<'_>,
        prev: Option<&Self::State>,
        cur: &mut Self::State,
        emit: &mut dyn FnMut(FileState),
    ) -> Result<DriverExtra>;
}

/// The scan of a [`TypedScanner`]: the driver and the current state.
struct Typed<'a, T: TypedScanner> {
    sc: &'a T,
    cur: T::State,
}

#[derive(Serialize)]
struct Versioned<'a, S> {
    version: u32,
    state: &'a S,
}

#[derive(serde::Deserialize)]
struct Stored {
    version: u32,
    state: serde_json::Value,
}

/// `b` as a state of `T`, or why it cannot be used.
fn decode<T: TypedScanner>(b: &[u8]) -> std::result::Result<T::State, String> {
    let s: Stored = serde_json::from_slice(b).map_err(|e| format!("it cannot be read ({e})"))?;
    if s.version != T::STATE_VERSION {
        return Err(format!("it is version {}, not {}", s.version, T::STATE_VERSION));
    }
    serde_json::from_value(s.state).map_err(|e| format!("it cannot be read ({e})"))
}

impl<T: TypedScanner> FsScanner for T {
    fn identity(&self) -> Identity {
        TypedScanner::identity(self)
    }

    fn begin(&self) -> Result<Box<dyn ScanSession + '_>> {
        Ok(Box::new(Typed { sc: self, cur: self.current()? }))
    }
}

impl<T: TypedScanner> ScanSession for Typed<'_, T> {
    fn continuity(&self, prev: PrevState<'_>) -> Continuity {
        match decode::<T>(prev.state) {
            Ok(s) => self.sc.continuity(&s, &self.cur, prev.offline),
            Err(why) => Continuity::Broken(Degrade::new(
                T::STATE_CODE,
                format!("the previous {} state is not usable: {why}", TypedScanner::identity(self.sc).family),
            )),
        }
    }

    fn scan_files(&mut self, cx: &ScanContext<'_>, emit: &mut dyn FnMut(FileState)) -> Result<DriverExtra> {
        // A usable previous snapshot passed `continuity`, so its state decodes.
        let prev = match cx.prev_state() {
            Some(b) if cx.prev.is_some() => Some(
                decode::<T>(b)
                    .map_err(|why| crate::Error::corrupt(format_args!("the previous file-system state: {why}")))?,
            ),
            _ => None,
        };
        self.sc.scan_files(cx, prev.as_ref(), &mut self.cur, emit)
    }

    fn state(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&Versioned { version: T::STATE_VERSION, state: &self.cur })
            .map_err(|e| crate::Error::corrupt(format_args!("cannot encode the state: {e}")))
    }
}

/// [`Continuity::Broken`] with `code` when a counter went back from `prev` to `cur` (`what`
/// names it: "btrfs generation").
pub fn rewind(code: DegradeCode, what: &str, prev: u64, cur: u64) -> Option<Continuity> {
    (cur < prev).then(|| Continuity::Broken(Degrade::new(code, format!("{what} went back from {prev} to {cur}"))))
}
