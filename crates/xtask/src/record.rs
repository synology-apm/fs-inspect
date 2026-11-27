//! `record-fixture`: a capture (`fs-inspect capture`), a sparse or a raw image into
//! `fixtures/<fs>/<dir>/<name>.fsbs` with its README and manifest entries
//! ([`fs_inspect_testkit::record`]), then its golden file written and checked by the manifest
//! tests.

use crate::support::{cargo, fail, parse, root, run, usage_error};
use fs_inspect_testkit::record::{Request, record};
use std::path::PathBuf;

pub fn record_fixture(args: &[String]) -> bool {
    let a = parse(args, &["--force"], &["--fs", "--name", "--dir", "--issue", "--what", "--checks"], 1);
    let (Some(input), Some(fs), Some(name)) = (a.positional.first(), a.value("--fs"), a.value("--name")) else {
        usage_error("needs a capture or image, --fs and --name (cargo xtask help)");
    };
    let req = Request {
        input: PathBuf::from(input),
        fs: fs.to_string(),
        dir: a.value("--dir").unwrap_or("reported").to_string(),
        name: name.to_string(),
        issue: a.value("--issue").map(str::to_string),
        what: a.value("--what").map(str::to_string),
        checks: a.value("--checks").unwrap_or("golden").split(',').map(str::to_string).collect(),
        force: a.flag("--force"),
    };
    let r = match record(&root().join("fixtures"), &req) {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    eprintln!("recorded {} ({} bytes, SHA-256 {})", r.path.display(), r.bytes, r.sha256);
    let test = |update: bool| {
        let mut c = cargo();
        c.args(["test", "--quiet", "-p", "fs-inspect", "--test", "fixture_manifest", "--", "--exact", &r.test]);
        if update {
            c.env("UPDATE_GOLDEN", "1");
        }
        run(if update { "golden file (UPDATE_GOLDEN=1)" } else { "its test" }, c)
    };
    if req.checks.iter().any(|c| c == "golden") && !test(true) {
        return false;
    }
    test(false)
}
