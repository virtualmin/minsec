//! minsec core: log sources → filters → tracker/policy → firewall backend.
//!
//! Design goals (see docs/PLAN.md): streaming (no retained log lines), bounded
//! memory, kernel-owned ban state, single-threaded event loop.

pub mod backend;
pub mod builtin;
pub mod config;
pub mod control;
pub mod duration;
pub mod engine;
pub mod events;
pub mod filter;
pub mod ip;
pub mod source;
pub mod tracker;

pub use config::Config;
pub use filter::{CompiledFilter, FilterDef, Match};
