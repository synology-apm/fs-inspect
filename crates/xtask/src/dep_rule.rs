//! `lint`'s dependency rule: every dependency comes from a registry or from this workspace, so
//! the repository builds on its own.

use crate::support::{cargo, echo, fail, step};
use std::path::Path;

/// The dependency rule broken by the packages of `metadata` (`cargo metadata` JSON), one line
/// each: every dependency comes from a registry or from this workspace, so the repository builds
/// on its own (no git dependency, no path dependency outside it).
fn dependency_violations(metadata: &serde_json::Value) -> Vec<String> {
    let root = Path::new(metadata["workspace_root"].as_str().unwrap_or_default());
    let mut out = Vec::new();
    for p in metadata["packages"].as_array().into_iter().flatten() {
        let name = p["name"].as_str().unwrap_or_default();
        for d in p["dependencies"].as_array().into_iter().flatten() {
            let dep = d["name"].as_str().unwrap_or_default();
            let (source, path) = (d["source"].as_str(), d["path"].as_str());
            let ok = match source {
                Some(s) => s.starts_with("registry+") || s.starts_with("sparse+"),
                None => path.is_some_and(|p| Path::new(p).starts_with(root)),
            };
            if !ok {
                let from = source.or(path).unwrap_or("?");
                out.push(format!("{name} depends on {dep} from {from}: only registry crates and this workspace's"));
            }
        }
    }
    out
}

/// [`dependency_violations`] of the workspace; false (and each printed) when there are any.
pub fn dependencies_ok() -> bool {
    step("dependency rule");
    let mut c = cargo();
    c.args(["metadata", "--format-version", "1", "--no-deps"]);
    echo(&c);
    let out = match c.output() {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => return fail(format!("cargo metadata failed: {}", String::from_utf8_lossy(&o.stderr))),
        Err(e) => return fail(format!("cargo metadata could not start: {e}")),
    };
    let v: serde_json::Value = match serde_json::from_slice(&out) {
        Ok(v) => v,
        Err(e) => return fail(format!("cargo metadata output: {e}")),
    };
    let bad = dependency_violations(&v);
    for b in &bad {
        fail(b);
    }
    bad.is_empty()
}

#[cfg(test)]
mod tests {
    use super::dependency_violations;
    use serde_json::json;

    #[test]
    fn only_registry_and_workspace_dependencies() {
        let path = |name: &str, p: &str| json!({"name": name, "source": null, "path": p});
        let from = |name: &str, s: &str| json!({"name": name, "source": s});
        let m = json!({"workspace_root": "/w/repo", "packages": [
            {"name": "a", "dependencies": [
                path("a-core", "/w/repo/crates/a-core"),
                from("serde", "registry+https://github.com/rust-lang/crates.io-index"),
                from("libc", "sparse+https://index.crates.io/"),
            ]},
            {"name": "a-testkit", "dependencies": [path("other", "/w/other/crates/other")]},
            {"name": "bench", "dependencies": [from("x", "git+https://example.com/x")]},
        ]});
        let v = dependency_violations(&m);
        assert_eq!(v.len(), 2, "{v:?}");
        assert!(v[0].starts_with("a-testkit depends on other from /w/other/crates/other:"));
        assert!(v[1].starts_with("bench depends on x from git+https://example.com/x:"));
    }
}
