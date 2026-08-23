//! Golden corpus: every `tests/corpus/<filter>.txt` at the repo root is run
//! against the built-in filter of the same name.

use minsec_core::{builtin, CompiledFilter};
use std::net::IpAddr;
use std::path::PathBuf;

#[test]
fn corpus() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus");
    let mut seen = 0;
    let mut failures = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("corpus dir") {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "txt") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let def = builtin::get(&name)
            .unwrap_or_else(|| panic!("corpus {name}.txt has no built-in filter"))
            .unwrap();
        let flt = CompiledFilter::compile(def).unwrap();
        for (lineno, raw) in std::fs::read_to_string(&path).unwrap().lines().enumerate() {
            let raw = raw.trim_end();
            if raw.is_empty() || raw.starts_with('#') {
                continue;
            }
            seen += 1;
            let at = format!("{name}.txt:{}", lineno + 1);
            if let Some(rest) = raw.strip_prefix("+ ") {
                let (ip, line) = rest.split_once(char::is_whitespace).expect("`+ <ip> <line>`");
                let want: IpAddr = ip.parse().unwrap_or_else(|_| panic!("{at}: bad ip {ip}"));
                match flt.match_line(line.trim_start()) {
                    Some(m) if m.ip == want => {}
                    Some(m) => failures.push(format!("{at}: matched {} but expected {want}", m.ip)),
                    None => failures.push(format!("{at}: no match: {line}")),
                }
            } else if let Some(line) = raw.strip_prefix("- ") {
                if let Some(m) = flt.match_line(line) {
                    failures.push(format!("{at}: unexpected match ({}) on: {line}", m.ip));
                }
            } else {
                panic!("{at}: lines must start with `+ <ip> ` or `- `");
            }
        }
    }
    assert!(seen > 0, "no corpus cases found in {}", dir.display());
    assert!(failures.is_empty(), "corpus failures:\n  {}", failures.join("\n  "));
}
