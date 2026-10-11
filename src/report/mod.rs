//! Human-readable output: plain-text tables and key/value blocks.
//!
//! Deliberately dependency-free (no TUI, no color crates) so the binary
//! stays lean and output is diffable in CI logs. Every command also offers
//! `--json` for machine consumption.

/// Print a padded `key: value` block.
pub fn kv(rows: &[(String, String)]) {
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (k, v) in rows {
        println!("  {k:<width$}  {v}", width = width);
    }
}

/// Print a table with auto-sized, capped columns.
pub fn table(headers: &[&str], rows: &[Vec<String>]) {
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().take(cols).enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }
    const CAP: usize = 44;
    let widths: Vec<usize> = widths.into_iter().map(|w| w.min(CAP)).collect();

    let line = |cells: &[String]| {
        let mut out = String::new();
        for (i, w) in widths.iter().enumerate() {
            out.push_str(&format!(
                "{:<width$}",
                cells.get(i).map(String::as_str).unwrap_or(""),
                width = w
            ));
            out.push_str("  ");
        }
        println!("{}", out.trim_end());
    };

    let header_cells: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    line(&header_cells);
    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    line(&sep);
    for row in rows {
        line(row);
    }
}

/// Truncate long cell values to keep tables readable.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max - 1).collect();
        format!("{cut}\u{2026}")
    }
}

pub fn status_label(active: bool) -> &'static str {
    if active { "ACTIVE" } else { "suppressed" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_long_strings() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(
            truncate("a-very-long-component-name-here", 10),
            "a-very-lo\u{2026}"
        );
    }
}
