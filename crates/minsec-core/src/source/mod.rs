//! Log sources. Every source pushes [`Line`]s into one channel consumed by the
//! engine; the engine routes by `origin`.

pub mod file;
pub mod journal;

use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Origin {
    /// A followed file, by canonical path pattern as configured.
    File(Arc<str>),
    /// A journald entry with its routing fields.
    ///
    /// `unit` and `uid` come from journald's trusted (`_`-prefixed) fields,
    /// which the sender cannot forge. `identifier` is client-supplied
    /// (`logger -t sshd` sets it freely) and `comm` is trivially chosen by
    /// renaming a binary, so the engine only honours those two when `uid`
    /// is a system account.
    Journal {
        unit: Option<Arc<str>>,
        identifier: Option<Arc<str>>,
        comm: Option<Arc<str>>,
        uid: Option<u32>,
    },
}

#[derive(Debug)]
pub struct Line {
    pub origin: Origin,
    pub text: String,
}
