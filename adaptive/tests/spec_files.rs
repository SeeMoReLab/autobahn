//! Load the checked-in failure specs of the parent repo through the fault
//! controller under both protocol sections, so a spec edit that the controller
//! rejects (a `leader` token, an `interval`, a missing delay) fails here
//! instead of at node start-up on CloudLab. Skips silently when the parent
//! repo's config directory is not present (the crate built standalone).

use adaptive::failure::{FaultController, ProtocolSection};
use std::path::PathBuf;

fn parent_config_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../config")
        .canonicalize()
        .ok()?;
    dir.is_dir().then_some(dir)
}

#[test]
fn checked_in_specs_load_under_both_sections() {
    let Some(config) = parent_config_dir() else {
        eprintln!("parent config directory not found; skipping");
        return;
    };
    let specs = [
        "autobahn/failure_spec.xml",
        "autobahn/failure_spec_timeout_demo.xml",
        "hotstuff/failure_spec.xml",
    ];
    for rel in specs {
        let path = config.join(rel);
        if !path.is_file() {
            eprintln!("{} not found; skipping", path.display());
            continue;
        }
        let path = path.to_str().unwrap();
        for section in [ProtocolSection::Autobahn, ProtocolSection::Hotstuff] {
            FaultController::load_file(path, 0, section)
                .unwrap_or_else(|e| panic!("{} under {:?}: {:#}", rel, section, e));
        }
    }
}
