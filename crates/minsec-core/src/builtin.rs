//! Filters compiled into the binary. Files under `filters/` at the repo root.

use crate::filter::FilterDef;

macro_rules! builtin {
    ($($name:literal),* $(,)?) => {
        pub const BUILTIN: &[(&str, &str)] = &[
            $(($name, include_str!(concat!("../../../filters/", $name, ".toml"))),)*
        ];
    };
}

builtin!(
    "sshd",
    "postfix",
    "postfix-sasl",
    "dovecot",
    "proftpd",
    "webmin",
    "apache-auth",
    "nginx-auth",
    "wordpress",
    "roundcube",
);

pub fn names() -> impl Iterator<Item = &'static str> {
    BUILTIN.iter().map(|(n, _)| *n)
}

pub fn get(name: &str) -> Option<anyhow::Result<FilterDef>> {
    BUILTIN
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, src)| FilterDef::from_toml(src).map_err(|e| anyhow::anyhow!("builtin filter `{name}`: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::CompiledFilter;

    #[test]
    fn all_builtins_compile() {
        for (name, _) in BUILTIN {
            let def = get(name).unwrap().unwrap();
            assert_eq!(&def.name, name, "filter name must match file name");
            CompiledFilter::compile(def).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }
}
