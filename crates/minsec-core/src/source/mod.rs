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
    Journal {
        unit: Option<Arc<str>>,
        identifier: Option<Arc<str>>,
        comm: Option<Arc<str>>,
    },
}

#[derive(Debug)]
pub struct Line {
    pub origin: Origin,
    pub text: String,
}
