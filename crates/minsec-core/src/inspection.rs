//! Stable, offline machine-readable inspection and validation interfaces.

use crate::config::{BackendKind, Config, Escalate, FilterConfig};
use crate::filter::{FilterDef, JournalSelector};
use crate::{builtin, CompiledFilter};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inspection {
    pub schema_version: u32,
    pub ok: bool,
    pub version: String,
    pub paths: InspectionPaths,
    pub files: InspectionFiles,
    pub effective: EffectiveConfig,
    pub filters: Vec<FilterInspection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InspectionPaths {
    pub config_dir: PathBuf,
    pub main_config: PathBuf,
    pub conf_dir: PathBuf,
    pub filters_dir: PathBuf,
    pub control_socket: PathBuf,
    pub state_dir: PathBuf,
    pub events_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InspectionFiles {
    pub main: Option<PathBuf>,
    pub dropins: Vec<PathBuf>,
    pub custom_filters: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectiveConfig {
    pub defaults: EffectiveDefaults,
    pub paths: EffectivePaths,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectiveDefaults {
    pub bantime_seconds: u64,
    pub findtime_seconds: u64,
    pub maxretry: u32,
    pub escalate_enabled: bool,
    pub escalate: EffectiveEscalate,
    pub allow: Vec<IpNet>,
    pub backend: BackendKind,
    pub exec_command: Option<String>,
    pub ipv6_prefix: u8,
    pub max_tracked: usize,
    pub journal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectiveEscalate {
    pub factor: u32,
    pub max_seconds: u64,
    pub memory_seconds: u64,
}

impl From<&Escalate> for EffectiveEscalate {
    fn from(value: &Escalate) -> Self {
        Self {
            factor: value.factor,
            max_seconds: value.max.secs(),
            memory_seconds: value.memory.secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectivePaths {
    pub socket: PathBuf,
    pub state_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilterInspection {
    pub name: String,
    pub builtin: bool,
    pub enabled: bool,
    pub source: String,
    pub definition: FilterDef,
    pub configured_override: Option<FilterConfig>,
    pub effective_policy: EffectivePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectivePolicy {
    pub bantime_seconds: u64,
    pub findtime_seconds: u64,
    pub maxretry: u32,
    pub escalation: bool,
    pub files: Vec<String>,
    pub journal: JournalSelector,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckResult {
    pub schema_version: u32,
    pub ok: bool,
    pub checked_filters: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<CheckError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckError {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    pub error: String,
}

pub fn inspect(config_dir: &Path, version: &str) -> anyhow::Result<Inspection> {
    let cfg = Config::load_dir(config_dir)?;
    let files = discover_files(config_dir);
    let mut filters = Vec::new();
    for name in all_filter_names(&cfg, &files) {
        let custom_path = config_dir.join("filters").join(format!("{name}.toml"));
        let custom = custom_path.is_file();
        let definition = raw_filter_def(&name, &custom_path, custom)?;
        let effective_definition = cfg.filter_def(&name)?;
        let policy = cfg.policy_for(&name, &effective_definition);
        filters.push(FilterInspection {
            name: name.clone(),
            builtin: builtin::get(&name).is_some(),
            enabled: cfg.filters.get(&name).is_some_and(|f| f.enabled),
            source: if custom {
                custom_path.display().to_string()
            } else {
                "built-in".to_string()
            },
            definition,
            configured_override: cfg.filters.get(&name).cloned(),
            effective_policy: EffectivePolicy {
                bantime_seconds: policy.bantime.as_secs(),
                findtime_seconds: policy.findtime.as_secs(),
                maxretry: policy.maxretry,
                escalation: policy.escalate.is_some(),
                files: effective_definition.files,
                journal: effective_definition.journal,
                ports: policy.ports,
            },
        });
    }
    Ok(Inspection {
        schema_version: SCHEMA_VERSION,
        ok: true,
        version: version.to_string(),
        paths: InspectionPaths {
            config_dir: config_dir.to_path_buf(),
            main_config: config_dir.join("minsec.toml"),
            conf_dir: config_dir.join("conf.d"),
            filters_dir: config_dir.join("filters"),
            control_socket: cfg.paths.socket.clone(),
            state_dir: cfg.paths.state_dir.clone(),
            events_file: cfg.paths.state_dir.join("events.jsonl"),
        },
        files,
        effective: EffectiveConfig {
            defaults: EffectiveDefaults {
                bantime_seconds: cfg.defaults.bantime.secs(),
                findtime_seconds: cfg.defaults.findtime.secs(),
                maxretry: cfg.defaults.maxretry,
                escalate_enabled: cfg.defaults.escalate_enabled,
                escalate: (&cfg.defaults.escalate).into(),
                allow: cfg.defaults.allow.clone(),
                backend: cfg.defaults.backend,
                exec_command: cfg.defaults.exec_command.clone(),
                ipv6_prefix: cfg.defaults.ipv6_prefix,
                max_tracked: cfg.defaults.max_tracked,
                journal: cfg.defaults.journal,
            },
            paths: EffectivePaths {
                socket: cfg.paths.socket,
                state_dir: cfg.paths.state_dir,
            },
        },
        filters,
    })
}

pub fn check(config_dir: &Path, all: bool) -> CheckResult {
    let cfg = match Config::load_dir(config_dir) {
        Ok(cfg) => cfg,
        Err(error) => {
            return CheckResult {
                schema_version: SCHEMA_VERSION,
                ok: false,
                checked_filters: Vec::new(),
                errors: vec![CheckError {
                    filter: None,
                    error: format!("{error:#}"),
                }],
            };
        }
    };
    let files = discover_files(config_dir);
    let names: Vec<String> = if all {
        all_filter_names(&cfg, &files).into_iter().collect()
    } else {
        cfg.enabled_filters().map(String::from).collect()
    };
    let mut checked_filters = Vec::new();
    let mut errors = Vec::new();
    for name in names {
        checked_filters.push(name.clone());
        match cfg.filter_def(&name).and_then(CompiledFilter::compile) {
            Ok(_) => {}
            Err(error) => errors.push(CheckError {
                filter: Some(name),
                error: format!("{error:#}"),
            }),
        }
    }
    CheckResult {
        schema_version: SCHEMA_VERSION,
        ok: errors.is_empty(),
        checked_filters,
        errors,
    }
}

fn discover_files(config_dir: &Path) -> InspectionFiles {
    let main = config_dir.join("minsec.toml");
    InspectionFiles {
        main: main.is_file().then_some(main),
        dropins: toml_files(&config_dir.join("conf.d")),
        custom_filters: toml_files(&config_dir.join("filters")),
    }
}

fn toml_files(directory: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(directory)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|extension| extension == "toml"))
        .collect();
    files.sort();
    files
}

fn all_filter_names(cfg: &Config, files: &InspectionFiles) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = builtin::names().map(String::from).collect();
    names.extend(cfg.filters.keys().cloned());
    names.extend(files.custom_filters.iter().filter_map(|path| {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .map(String::from)
    }));
    names
}

fn raw_filter_def(name: &str, custom_path: &Path, custom: bool) -> anyhow::Result<FilterDef> {
    if custom {
        let source = std::fs::read_to_string(custom_path)?;
        return FilterDef::from_toml(&source)
            .map_err(|error| anyhow::anyhow!("{}: {error}", custom_path.display()));
    }
    builtin::get(name)
        .ok_or_else(|| anyhow::anyhow!("unknown filter `{name}`"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_config() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("minsec-inspection-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(directory.join("conf.d")).unwrap();
        std::fs::create_dir_all(directory.join("filters")).unwrap();
        directory
    }

    #[test]
    fn schema_reports_merged_configuration_and_custom_filters() {
        let directory = temp_config();
        std::fs::write(
            directory.join("minsec.toml"),
            r#"
[defaults]
bantime = "2h"
[filters.sshd]
enabled = true
"#,
        )
        .unwrap();
        std::fs::write(directory.join("conf.d/10-local.toml"), "[defaults]\nmaxretry = 7\n").unwrap();
        std::fs::write(
            directory.join("filters/custom.toml"),
            r#"
name = "custom"
patterns = ["failed from <HOST>"]
"#,
        )
        .unwrap();

        let inspection = inspect(&directory, "test-version").unwrap();
        assert_eq!(inspection.schema_version, 1);
        assert_eq!(inspection.effective.defaults.bantime_seconds, 7200);
        assert_eq!(inspection.effective.defaults.maxretry, 7);
        assert!(inspection.filters.iter().any(|filter| filter.name == "custom" && !filter.enabled));
        assert_eq!(inspection.files.dropins.len(), 1);
        assert_eq!(inspection.files.custom_filters.len(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn check_all_compiles_disabled_custom_filters() {
        let directory = temp_config();
        std::fs::write(
            directory.join("filters/custom.toml"),
            r#"
name = "custom"
patterns = ["failed from <HOST>"]
"#,
        )
        .unwrap();
        let enabled_only = check(&directory, false);
        assert!(!enabled_only.checked_filters.contains(&"custom".to_string()));
        let all = check(&directory, true);
        assert!(all.ok);
        assert!(all.checked_filters.contains(&"custom".to_string()));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
