//! Version comparison: strict semver when possible, pragmatic otherwise.
//!
//! OSV `SEMVER` and `ECOSYSTEM` ranges follow
//! [the OSV specification](https://ossf.github.io/osv-schema/), which
//! evaluates a version against a sorted list of `introduced` / `fixed` /
//! `last_affected` events. Real-world SBOMs also contain versions that are
//! not strict semver (firmware builds, distro suffixes), so the comparator
//! falls back to a numeric-aware tokenizer instead of failing.

use std::cmp::Ordering;

#[derive(Debug, PartialEq)]
enum Strict {
    Semver {
        major: u64,
        minor: u64,
        patch: u64,
        pre: Vec<Id>,
    },
}

#[derive(Debug, PartialEq)]
enum Id {
    Num(u64),
    Word(String),
}

fn parse_strict(s: &str) -> Option<Strict> {
    let no_build = s.split('+').next().unwrap_or(s);
    let (core, pre_raw) = match no_build.split_once('-') {
        Some((a, b)) => (a, Some(b)),
        None => (no_build, None),
    };

    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let mut nums = [0u64; 3];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // no leading zeroes allowed in strict semver
        if p.len() > 1 && p.starts_with('0') {
            return None;
        }
        nums[i] = p.parse().ok()?;
    }

    let mut pre = Vec::new();
    if let Some(p) = pre_raw {
        for id in p.split('.') {
            if id.is_empty() {
                return None;
            }
            if id.bytes().all(|b| b.is_ascii_digit()) {
                if id.len() > 1 && id.starts_with('0') {
                    return None;
                }
                pre.push(Id::Num(id.parse().ok()?));
            } else {
                pre.push(Id::Word(id.to_string()));
            }
        }
    }

    Some(Strict::Semver {
        major: nums[0],
        minor: nums[1],
        patch: nums[2],
        pre,
    })
}

fn cmp_strict(a: &Strict, b: &Strict) -> Ordering {
    let (
        Strict::Semver {
            major: am,
            minor: an,
            patch: ap,
            pre: ap_,
        },
        Strict::Semver {
            major: bm,
            minor: bn,
            patch: bp,
            pre: bp_,
        },
    ) = (a, b);
    let core = am.cmp(bm).then(an.cmp(bn)).then(ap.cmp(bp));
    if core != Ordering::Equal {
        return core;
    }
    // no pre-release sorts *after* any pre-release
    match (ap_.is_empty(), bp_.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => {
            for (x, y) in ap_.iter().zip(bp_.iter()) {
                let ord = match (x, y) {
                    (Id::Num(u), Id::Num(v)) => u.cmp(v),
                    (Id::Num(_), Id::Word(_)) => Ordering::Less,
                    (Id::Word(_), Id::Num(_)) => Ordering::Greater,
                    (Id::Word(u), Id::Word(v)) => u.cmp(v),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            ap_.len().cmp(&bp_.len())
        }
    }
}

fn cmp_lenient(a: &str, b: &str) -> Ordering {
    let ta = tokenize(a);
    let tb = tokenize(b);
    for (x, y) in ta.iter().zip(tb.iter()) {
        let ord = match (x, y) {
            (Seg::Num(u), Seg::Num(v)) => u.cmp(v),
            (Seg::Num(_), Seg::Word(_)) => Ordering::Less,
            (Seg::Word(_), Seg::Num(_)) => Ordering::Greater,
            (Seg::Word(u), Seg::Word(v)) => {
                let lu = u.to_ascii_lowercase();
                let lv = v.to_ascii_lowercase();
                lu.cmp(&lv)
            }
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    ta.len().cmp(&tb.len())
}

#[derive(Debug, PartialEq)]
enum Seg {
    Num(u64),
    Word(String),
}

fn tokenize(s: &str) -> Vec<Seg> {
    let trimmed = s.trim().trim_start_matches(['v', 'V', '=']);
    let mut out = Vec::new();
    let mut current = String::new();
    let mut current_is_num = false;
    let mut current_nonempty = false;

    let flush = |current: &mut String,
                 current_is_num: &mut bool,
                 current_nonempty: &mut bool,
                 out: &mut Vec<Seg>| {
        if *current_nonempty {
            if *current_is_num {
                if let Ok(n) = current.parse::<u64>() {
                    out.push(Seg::Num(n));
                } else {
                    out.push(Seg::Word(current.clone()));
                }
            } else {
                out.push(Seg::Word(current.clone()));
            }
        }
        current.clear();
        *current_is_num = false;
        *current_nonempty = false;
    };

    for c in trimmed.chars() {
        if c.is_ascii_digit() {
            if current_nonempty && !current_is_num {
                flush(
                    &mut current,
                    &mut current_is_num,
                    &mut current_nonempty,
                    &mut out,
                );
            }
            current.push(c);
            current_is_num = true;
            current_nonempty = true;
        } else if c.is_ascii_alphabetic() || c == '+' || c == '*' {
            if current_nonempty && current_is_num {
                flush(
                    &mut current,
                    &mut current_is_num,
                    &mut current_nonempty,
                    &mut out,
                );
            }
            current.push(c);
            current_is_num = false;
            current_nonempty = true;
        } else {
            // separators: . - _ : space and anything else split tokens
            flush(
                &mut current,
                &mut current_is_num,
                &mut current_nonempty,
                &mut out,
            );
        }
    }
    flush(
        &mut current,
        &mut current_is_num,
        &mut current_nonempty,
        &mut out,
    );
    out
}

/// Compare two version strings.
///
/// Both strict semver: semver ordering (pre-release < release, numeric
/// identifiers compare numerically and sort before alphanumeric ones).
/// Otherwise: segment-wise comparison, digit runs compare numerically.
pub fn cmp(a: &str, b: &str) -> Ordering {
    let a = a.trim();
    let b = b.trim();
    if a == b {
        return Ordering::Equal;
    }
    match (parse_strict(a), parse_strict(b)) {
        (Some(sa), Some(sb)) => cmp_strict(&sa, &sb),
        _ => cmp_lenient(a, b),
    }
}

/// `true` when `version` is greater than or equal to `other`.
pub fn ge(version: &str, other: &str) -> bool {
    cmp(version, other) != Ordering::Less
}

/// `true` when `version` is strictly greater than `other`.
pub fn gt(version: &str, other: &str) -> bool {
    cmp(version, other) == Ordering::Greater
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_semver_ordering() {
        assert_eq!(cmp("1.2.13", "1.2.13"), Ordering::Equal);
        assert_eq!(cmp("1.2.12", "1.2.13"), Ordering::Less);
        assert_eq!(cmp("3.0.12", "3.0.13"), Ordering::Less);
        assert_eq!(cmp("1.36.0", "1.36.1"), Ordering::Less);
        assert_eq!(cmp("1.0.0", "1.0.0-rc1"), Ordering::Greater);
        assert_eq!(cmp("1.0.0-alpha", "1.0.0-beta"), Ordering::Less);
        assert_eq!(cmp("1.0.0-1", "1.0.0-alpha"), Ordering::Less);
        assert_eq!(cmp("1.0.0-1.2", "1.0.0-1"), Ordering::Greater);
        assert_eq!(cmp("2.0.0", "10.0.0"), Ordering::Less);
        assert_eq!(cmp("1.11.1", "1.11.0"), Ordering::Greater);
    }

    #[test]
    fn lenient_fallback() {
        assert_eq!(cmp("1.2", "1.2.1"), Ordering::Less);
        assert_eq!(cmp("1.2", "1.2"), Ordering::Equal);
        assert_eq!(cmp("2024a", "2024b"), Ordering::Less);
        assert_eq!(cmp("2.4p5", "2.4p6"), Ordering::Less);
        assert_eq!(cmp("4.17", "4.2"), Ordering::Greater);
    }

    #[test]
    fn helpers() {
        assert!(ge("3.0.13", "3.0.12"));
        assert!(!ge("3.0.12", "3.0.13"));
        assert!(gt("1.36.1", "1.36.0"));
    }
}
