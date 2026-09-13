//! Shared formatting helpers for the TUI: byte sizes, relative timestamps,
//! durations, home-directory abbreviation, and unicode-width-aware string
//! truncation. Centralizing these avoids each render module hand-rolling its
//! own (subtly different) humansize/path-shortening logic.

use std::path::Path;
use std::time::{Duration, SystemTime};

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Human-readable byte size, e.g. `"512 KiB"`.
pub fn bytes(b: u64) -> String {
    humansize::format_size(b, humansize::BINARY)
}

/// Compact byte size (≤5 chars) for tight columns, e.g. `"512M"`, `"1.2G"`,
/// `"37K"`, `"0B"`. Binary units; one decimal place when the value is under
/// 10 of its unit, none otherwise.
pub fn bytes_compact(b: u64) -> String {
    const UNITS: [(u64, char); 4] = [
        (1u64 << 40, 'T'),
        (1u64 << 30, 'G'),
        (1u64 << 20, 'M'),
        (1u64 << 10, 'K'),
    ];
    for (factor, unit) in UNITS {
        if b >= factor {
            let value = b as f64 / factor as f64;
            return if value < 10.0 {
                format!("{value:.1}{unit}")
            } else {
                format!("{value:.0}{unit}")
            };
        }
    }
    format!("{b}B")
}

/// Size cell text: the human size, `…` while a size is still pending, else
/// blank. `pending` should be true only while the section producing the size
/// is still scanning — once it's done, a `None` size means "no size concept
/// for this finding" and should render blank, not a perpetual `…`.
pub fn bytes_opt(b: Option<u64>, pending: bool) -> String {
    match b {
        Some(b) => bytes(b),
        None if pending => "…".to_string(),
        None => String::new(),
    }
}

/// `YYYY-MM-DD` (UTC) for a timestamp — enough precision for "when was this
/// last touched" without pulling in a date crate. Pre-1970 reads as
/// `1970-01-01`.
pub fn iso_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Coarse relative-time label, e.g. `"5m ago"`, `"3h ago"`, `"2d ago"`.
/// A `t` in the future (clock skew, etc.) also reads as `"just now"` rather
/// than a nonsensical negative duration.
pub fn humanize_ago(t: SystemTime, now: SystemTime) -> String {
    let secs = match now.duration_since(t) {
        Ok(d) => d.as_secs(),
        Err(_) => return "just now".to_string(),
    };
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    const MONTH: u64 = 30 * DAY;
    const YEAR: u64 = 365 * DAY;
    if secs < MINUTE {
        "just now".to_string()
    } else if secs < HOUR {
        format!("{}m ago", secs / MINUTE)
    } else if secs < DAY {
        format!("{}h ago", secs / HOUR)
    } else if secs < MONTH {
        format!("{}d ago", secs / DAY)
    } else if secs < YEAR {
        format!("{}mo ago", secs / MONTH)
    } else {
        format!("{}y ago", secs / YEAR)
    }
}

/// Coarse duration label, e.g. `"850ms"`, `"1.2s"`, `"2m 05s"`, `"1h 02m"`.
pub fn humanize_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        return format!("{ms}ms");
    }
    let secs = d.as_secs();
    if secs < 60 {
        format!("{:.1}s", d.as_secs_f64())
    } else if secs < 3600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Display path with the user's home abbreviated to `~` (macOS `/Users/<u>/…`).
pub fn abbrev_home(p: &Path) -> String {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("/Users/") {
        if let Some(idx) = rest.find('/') {
            return format!("~{}", &rest[idx..]);
        }
    }
    s.into_owned()
}

/// Truncate `s` to display width `width`, appending `…` (width 1) when
/// truncation occurs. The result's display width is always `<= width`.
/// `width == 0` yields the empty string.
pub fn truncate_end(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if UnicodeWidthStr::width(s) <= width {
        return s.to_string();
    }
    let budget = width - 1; // reserve room for the ellipsis
    let mut out = String::new();
    let mut w = 0usize;
    for c in s.chars() {
        let cw = UnicodeWidthChar::width(c).unwrap_or(0);
        if w + cw > budget {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push('…');
    out
}

/// Truncate `s` to display width `width` by removing characters from the
/// middle, replacing them with a single `…`. Useful for paths, where the
/// tail (filename) and the head (mount/volume) are both more informative
/// than the middle. The result's display width is always `<= width`.
/// `width == 0` yields the empty string.
pub fn truncate_middle(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if UnicodeWidthStr::width(s) <= width {
        return s.to_string();
    }
    if width == 1 {
        return "…".to_string();
    }
    let budget = width - 1; // reserve room for the ellipsis
    let head_budget = budget / 2;
    let tail_budget = budget - head_budget;

    let chars: Vec<char> = s.chars().collect();

    let mut head = String::new();
    let mut hw = 0usize;
    let mut head_end = 0usize;
    for (i, &c) in chars.iter().enumerate() {
        let cw = UnicodeWidthChar::width(c).unwrap_or(0);
        if hw + cw > head_budget {
            break;
        }
        head.push(c);
        hw += cw;
        head_end = i + 1;
    }

    let mut tail = String::new();
    let mut tw = 0usize;
    for i in (head_end..chars.len()).rev() {
        let c = chars[i];
        let cw = UnicodeWidthChar::width(c).unwrap_or(0);
        if tw + cw > tail_budget {
            break;
        }
        tail.insert(0, c);
        tw += cw;
    }

    format!("{head}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_date_known_values() {
        let day = |n: u64| SystemTime::UNIX_EPOCH + Duration::from_secs(n * 86_400);
        assert_eq!(iso_date(day(0)), "1970-01-01");
        assert_eq!(iso_date(day(19_723)), "2024-01-01");
        assert_eq!(iso_date(day(20_694)), "2026-08-29");
    }

    #[test]
    fn abbreviates_home() {
        assert_eq!(
            abbrev_home(Path::new("/Users/nicky/dev/x/target")),
            "~/dev/x/target"
        );
    }

    #[test]
    fn non_home_path_untouched_and_missing_is_blank() {
        assert_eq!(
            abbrev_home(Path::new("/Library/x.plist")),
            "/Library/x.plist"
        );
        // "missing is blank" is now the caller's job: `Option<&Path>` maps to "".
        let missing: Option<&Path> = None;
        assert_eq!(missing.map(abbrev_home).unwrap_or_default(), "");
    }

    #[test]
    fn bytes_compact_examples() {
        assert_eq!(bytes_compact(0), "0B");
        assert_eq!(bytes_compact(37 * 1024), "37K");
        assert_eq!(bytes_compact(512 * 1024 * 1024), "512M");
        assert_eq!(
            bytes_compact((1.2 * 1024.0 * 1024.0 * 1024.0) as u64),
            "1.2G"
        );
    }

    #[test]
    fn bytes_opt_variants() {
        assert_eq!(bytes_opt(Some(1024), false), "1 KiB");
        assert_eq!(bytes_opt(None, true), "…");
        assert_eq!(bytes_opt(None, false), "");
    }

    #[test]
    fn humanize_ago_buckets() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert_eq!(humanize_ago(now - Duration::from_secs(30), now), "just now");
        assert_eq!(
            humanize_ago(now - Duration::from_secs(5 * 60), now),
            "5m ago"
        );
        assert_eq!(
            humanize_ago(now - Duration::from_secs(3 * 3600), now),
            "3h ago"
        );
        assert_eq!(
            humanize_ago(now - Duration::from_secs(2 * 86400), now),
            "2d ago"
        );
        assert_eq!(
            humanize_ago(now - Duration::from_secs(3 * 30 * 86400), now),
            "3mo ago"
        );
        assert_eq!(
            humanize_ago(now - Duration::from_secs(2 * 365 * 86400), now),
            "2y ago"
        );
        // Future timestamp reads as "just now" rather than a bogus negative.
        assert_eq!(humanize_ago(now + Duration::from_secs(10), now), "just now");
    }

    #[test]
    fn humanize_duration_buckets() {
        assert_eq!(humanize_duration(Duration::from_millis(850)), "850ms");
        assert_eq!(humanize_duration(Duration::from_millis(1200)), "1.2s");
        assert_eq!(humanize_duration(Duration::from_secs(125)), "2m 05s");
        assert_eq!(humanize_duration(Duration::from_secs(3720)), "1h 02m");
    }

    #[test]
    fn truncate_end_ascii() {
        assert_eq!(truncate_end("hello world", 5), "hell…");
        assert_eq!(truncate_end("hi", 5), "hi");
        assert_eq!(truncate_end("hello", 5), "hello"); // exact-fit: no ellipsis
        assert_eq!(truncate_end("anything", 0), "");
    }

    #[test]
    fn truncate_end_wide_chars() {
        // Each CJK ideograph is display-width 2; "你好世界" is width 8.
        let s = "你好世界";
        let out = truncate_end(s, 5);
        assert!(UnicodeWidthStr::width(out.as_str()) <= 5);
        assert!(out.ends_with('…'));
        // Exact-fit: width 8 needs no truncation.
        assert_eq!(truncate_end(s, 8), s);
    }

    #[test]
    fn truncate_middle_ascii() {
        let out = truncate_middle("abcdefghij", 7);
        assert!(out.contains('…'));
        assert!(UnicodeWidthStr::width(out.as_str()) <= 7);
        assert!(out.starts_with("abc"));
        assert!(out.ends_with("ij") || out.ends_with('j'));
        assert_eq!(truncate_middle("abc", 7), "abc"); // exact-fit
    }

    #[test]
    fn truncate_middle_wide_chars() {
        let s = "你好世界abcdef";
        let out = truncate_middle(s, 8);
        assert!(UnicodeWidthStr::width(out.as_str()) <= 8);
        assert!(out.contains('…'));
    }
}
