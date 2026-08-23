//! Human-friendly durations: "30s", "10m", "1h30m", "2d", "1w", or bare seconds.

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::time::Duration;

pub fn parse(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let mut total: u64 = 0;
    let mut num: u64 = 0;
    let mut have_num = false;
    let mut any = false;
    for c in s.chars() {
        if let Some(d) = c.to_digit(10) {
            num = num
                .checked_mul(10)
                .and_then(|n| n.checked_add(d as u64))
                .ok_or("duration overflow")?;
            have_num = true;
            continue;
        }
        if !have_num {
            return Err(format!("unexpected '{c}' in duration '{s}'"));
        }
        let mult = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return Err(format!("unknown unit '{c}' in duration '{s}'")),
        };
        total = total
            .checked_add(num.checked_mul(mult).ok_or("duration overflow")?)
            .ok_or("duration overflow")?;
        num = 0;
        have_num = false;
        any = true;
    }
    if have_num {
        total = total.checked_add(num).ok_or("duration overflow")?;
        any = true;
    }
    if !any {
        return Err(format!("invalid duration '{s}'"));
    }
    Ok(Duration::from_secs(total))
}

pub fn format(d: Duration) -> String {
    let mut s = d.as_secs();
    if s == 0 {
        return "0s".into();
    }
    let mut out = String::new();
    for (unit, mult) in [('w', 604_800u64), ('d', 86_400), ('h', 3600), ('m', 60), ('s', 1)] {
        if s >= mult {
            out.push_str(&format!("{}{}", s / mult, unit));
            s %= mult;
        }
    }
    out
}

/// Serde wrapper so config fields can be written as `"1h"`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HumanDuration(pub Duration);

impl HumanDuration {
    pub fn secs(&self) -> u64 {
        self.0.as_secs()
    }
}

impl From<Duration> for HumanDuration {
    fn from(d: Duration) -> Self {
        Self(d)
    }
}

impl fmt::Debug for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format(self.0))
    }
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format(self.0))
    }
}

impl Serialize for HumanDuration {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format(self.0))
    }
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> de::Visitor<'de> for V {
            type Value = HumanDuration;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a duration like \"10m\" or a number of seconds")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                parse(v).map(HumanDuration).map_err(E::custom)
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(HumanDuration(Duration::from_secs(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                if v < 0 {
                    return Err(E::custom("negative duration"));
                }
                Ok(HumanDuration(Duration::from_secs(v as u64)))
            }
        }
        d.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses() {
        assert_eq!(parse("30").unwrap().as_secs(), 30);
        assert_eq!(parse("10m").unwrap().as_secs(), 600);
        assert_eq!(parse("1h30m").unwrap().as_secs(), 5400);
        assert_eq!(parse("1w").unwrap().as_secs(), 604_800);
        assert!(parse("").is_err());
        assert!(parse("m").is_err());
        assert!(parse("5x").is_err());
    }
    #[test]
    fn formats() {
        assert_eq!(format(Duration::from_secs(5400)), "1h30m");
        assert_eq!(format(Duration::from_secs(0)), "0s");
    }
}
