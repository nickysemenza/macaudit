//! Point-in-time macOS resource-health scanner.
//!
//! This intentionally is not a monitor: every invocation samples a bounded set
//! of local commands once and emits ephemeral findings. The commands all flow
//! through `CommandRunner`, making parsers fixture-testable and cancellation
//! behave consistently with the rest of macaudit.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;

use crate::model::{Finding, FindingKind, ScannerId, Severity};
use crate::scan::{ScanCtx, Scanner};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_LIMIT: usize = 12;
/// Native macOS storage availability includes reclaimable space, such as local
/// Time Machine snapshots. JXA/osascript ships with macOS and avoids compiling
/// Swift on each manual scan.
const VOLUME_CAPACITY_SCRIPT: &str = r#"ObjC.import("Foundation"); const url = $.NSURL.fileURLWithPath("/"); function value(key) { const out = Ref(); url.getResourceValueForKeyError(out, key, null); return ObjC.unwrap(out[0]); } JSON.stringify({total:value($.NSURLVolumeTotalCapacityKey), physical:value($.NSURLVolumeAvailableCapacityKey), important:value($.NSURLVolumeAvailableCapacityForImportantUsageKey)});"#;

#[derive(Default)]
pub struct SystemScanner;

#[async_trait]
impl Scanner for SystemScanner {
    fn id(&self) -> ScannerId {
        ScannerId::System
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        ctx.progress("sampling host health", 0, Some(5)).await;

        let load = command(&ctx, "sysctl", &["-n", "vm.loadavg"]).await;
        let cpu_count = command(&ctx, "sysctl", &["-n", "hw.ncpu"]).await;
        if let Some(values) = load.as_deref().and_then(parse_loadavg) {
            let cores = cpu_count
                .as_deref()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0);
            let severity = if cores > 0 && values[0] > cores as f64 {
                Severity::Warning
            } else if cores > 0 && values[0] > cores as f64 * 0.75 {
                Severity::Attention
            } else {
                Severity::Info
            };
            ctx.emit(
                Finding::new(FindingKind::SystemMetric, "cpu-load", "CPU load")
                    .detail(format!(
                        "load average {:.2} / {:.2} / {:.2}{}",
                        values[0],
                        values[1],
                        values[2],
                        if cores > 0 { format!(" across {cores} cores") } else { String::new() }
                    ))
                    .severity(severity)
                    .ephemeral()
                    .provenance("sysctl -n vm.loadavg; sysctl -n hw.ncpu")
                    .meta(json!({ "role": "cpu", "load_1": values[0], "load_5": values[1], "load_15": values[2], "cores": cores })),
            )
            .await;
        }
        ctx.progress("sampling memory", 1, Some(5)).await;

        let mem_size = command(&ctx, "sysctl", &["-n", "hw.memsize"]).await;
        let vm_stat = command(&ctx, "vm_stat", &[]).await;
        let memory_pressure = command(&ctx, "memory_pressure", &["-Q"]).await;
        if let Some(memory) = vm_stat.as_deref().and_then(parse_vm_stat) {
            let total = mem_size
                .as_deref()
                .and_then(|s| s.trim().parse::<u64>().ok());
            let used = (memory.wired + memory.active + memory.inactive + memory.speculative)
                .saturating_mul(memory.page_size);
            let compressed = memory.compressed.saturating_mul(memory.page_size);
            let signal = memory_pressure.as_deref().and_then(parse_memory_signal);
            let severity = match signal {
                Some(MemorySignal::Pressure(p)) if p >= 80 => Severity::Warning,
                Some(MemorySignal::Pressure(p)) if p >= 50 => Severity::Attention,
                Some(MemorySignal::Free(p)) if p <= 10 => Severity::Warning,
                Some(MemorySignal::Free(p)) if p <= 30 => Severity::Attention,
                _ => Severity::Info,
            };
            let signal_detail = match signal {
                Some(MemorySignal::Pressure(p)) => format!("; {p}% pressure"),
                Some(MemorySignal::Free(p)) => format!("; {p}% free"),
                None => String::new(),
            };
            ctx.emit(
                Finding::new(FindingKind::SystemMetric, "memory", "Memory pressure")
                    .detail(match total {
                        Some(total) => format!(
                            "{} used of {}; {} compressed{}",
                            human(used), human(total), human(compressed), signal_detail
                        ),
                        None => format!("{} used; {} compressed{}", human(used), human(compressed), signal_detail),
                    })
                    .severity(severity)
                    .ephemeral()
                    .provenance("sysctl -n hw.memsize; vm_stat; memory_pressure -Q")
                    .meta(json!({ "role": "memory", "used_bytes": used, "total_bytes": total, "compressed_bytes": compressed, "pressure_percent": signal.and_then(|s| s.pressure()), "free_percent": signal.and_then(|s| s.free()) })),
            )
            .await;
        }

        let swap = command(&ctx, "sysctl", &["-n", "vm.swapusage"]).await;
        if let Some(swap) = swap.as_deref().and_then(parse_swapusage) {
            let severity = if swap.total > 0 && swap.used as f64 / swap.total as f64 >= 0.75 {
                Severity::Warning
            } else if swap.used > 0 {
                Severity::Attention
            } else {
                Severity::Info
            };
            ctx.emit(
                Finding::new(FindingKind::SystemMetric, "swap", "Swap")
                    .detail(format!("{} used of {}", human(swap.used), human(swap.total)))
                    .severity(severity)
                    .ephemeral()
                    .provenance("sysctl -n vm.swapusage")
                    .meta(json!({ "role": "swap", "used_bytes": swap.used, "total_bytes": swap.total })),
            )
            .await;
        }
        ctx.progress("sampling disk", 2, Some(5)).await;

        let disk = command(&ctx, "diskutil", &["info", "-plist", "/"]).await;
        let macos_capacity = command(
            &ctx,
            "osascript",
            &["-l", "JavaScript", "-e", VOLUME_CAPACITY_SCRIPT],
        )
        .await
        .and_then(|output| parse_macos_capacity(&output));
        let local_snapshot_count = command(&ctx, "tmutil", &["listlocalsnapshots", "/"])
            .await
            .map(|output| count_local_snapshots(&output));
        if let Some(disk) = disk.as_deref().and_then(parse_diskutil_info) {
            let available = macos_capacity
                .map(|capacity| capacity.important)
                .filter(|available| *available >= disk.free);
            let reclaimable = available.map(|available| available.saturating_sub(disk.free));
            let severity = if disk.capacity > 0 && disk.used as f64 / disk.capacity as f64 >= 0.95 {
                Severity::Warning
            } else if disk.capacity > 0 && disk.used as f64 / disk.capacity as f64 >= 0.85 {
                Severity::Attention
            } else {
                Severity::Info
            };
            ctx.emit(
                Finding::new(FindingKind::SystemMetric, "root-disk", "Root disk")
                    .detail(match (available, reclaimable, local_snapshot_count) {
                        (Some(available), Some(reclaimable), Some(snapshot_count)) => format!(
                            "{} used of {}; {} APFS free; {} macOS available (includes ~{} macOS-managed space: {snapshot_count} local Time Machine snapshots, whose exact bytes macOS does not report, plus other purgeable space it does not itemize)",
                            human(disk.used),
                            human(disk.capacity),
                            human(disk.free),
                            human(available),
                            human(reclaimable)
                        ),
                        (Some(available), Some(reclaimable), None) => format!(
                            "{} used of {}; {} APFS free; {} macOS available (includes ~{} macOS-managed reclaimable space; category breakdown unavailable)",
                            human(disk.used),
                            human(disk.capacity),
                            human(disk.free),
                            human(available),
                            human(reclaimable)
                        ),
                        _ => format!(
                            "{} used of {}; {} APFS free",
                            human(disk.used), human(disk.capacity), human(disk.free)
                        ),
                    })
                    // Root capacity is the one System metric that is useful
                    // in history; the live CPU/memory/process observations
                    // above remain ephemeral.
                    .size(disk.used)
                    .severity(severity)
                    .provenance("diskutil info -plist /; NSURLVolumeAvailableCapacityForImportantUsageKey via osascript")
                    .coverage("APFS free is immediately unallocated space. macOS available includes purgeable space and is an estimate that can change without deleting user files. Time Machine local snapshots are counted, but macOS does not report reliable per-snapshot or aggregate byte sizes.")
                    .meta(json!({ "role": "disk", "capacity_bytes": disk.capacity, "used_bytes": disk.used, "apfs_free_bytes": disk.free, "macos_available_bytes": available, "estimated_reclaimable_bytes": reclaimable, "local_time_machine_snapshot_count": local_snapshot_count })),
            )
            .await;
        }

        let ps = command(
            &ctx,
            "ps",
            &["-axo", "pid=,user=,%cpu=,%mem=,rss=,state=,comm="],
        )
        .await;
        if let Some(ps) = ps {
            for process in top_processes(parse_processes(&ps)) {
                let severity =
                    if process.cpu >= 100.0 || process.rss_bytes >= 4 * 1024 * 1024 * 1024 {
                        Severity::Warning
                    } else if process.cpu >= 50.0 || process.rss_bytes >= 1024 * 1024 * 1024 {
                        Severity::Attention
                    } else {
                        Severity::Info
                    };
                ctx.emit(
                    Finding::new(
                        FindingKind::ProcessResource,
                        &format!("{}:{}", process.pid, process.command),
                        format!("{} (pid {})", process.command, process.pid),
                    )
                    .detail(format!(
                        "{:.1}% CPU · {} resident · {} · {}",
                        process.cpu,
                        human(process.rss_bytes),
                        process.user,
                        process.state
                    ))
                    .severity(severity)
                    .ephemeral()
                    .provenance("ps -axo pid,user,%cpu,%mem,rss,state,comm")
                    .meta(json!({ "role": "process", "pid": process.pid, "user": process.user, "cpu_percent": process.cpu, "memory_percent": process.memory_percent, "rss_bytes": process.rss_bytes, "state": process.state, "command": process.command })),
                )
                .await;
            }
        }
        ctx.progress("resource snapshot complete", 5, Some(5)).await;
        Ok(())
    }
}

async fn command(ctx: &ScanCtx, program: &str, args: &[&str]) -> Option<String> {
    let result =
        tokio::time::timeout(COMMAND_TIMEOUT, ctx.runner.run(program, args, &ctx.token)).await;
    match result {
        Ok(Ok(out)) if out.success() => Some(out.stdout_str().into_owned()),
        _ => None,
    }
}

fn parse_loadavg(input: &str) -> Option<[f64; 3]> {
    let values: Vec<f64> = input
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    (values.len() >= 3).then(|| [values[0], values[1], values[2]])
}

#[derive(Debug, Clone, Copy)]
struct VmStat {
    page_size: u64,
    active: u64,
    inactive: u64,
    speculative: u64,
    wired: u64,
    compressed: u64,
}

fn parse_vm_stat(input: &str) -> Option<VmStat> {
    let mut page_size = 4096;
    let mut values = BTreeMap::new();
    for line in input.lines() {
        if let Some(n) = line
            .split("page size of ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
        {
            page_size = n.parse().ok()?;
        }
        let Some((key, raw)) = line.split_once(':') else {
            continue;
        };
        let Ok(value) = raw
            .trim()
            .trim_end_matches('.')
            .replace('.', "")
            .parse::<u64>()
        else {
            continue;
        };
        values.insert(key.trim().to_ascii_lowercase(), value);
    }
    Some(VmStat {
        page_size,
        active: *values.get("pages active")?,
        inactive: *values.get("pages inactive").unwrap_or(&0),
        speculative: *values.get("pages speculative").unwrap_or(&0),
        wired: *values.get("pages wired down").unwrap_or(&0),
        compressed: *values.get("pages occupied by compressor").unwrap_or(&0),
    })
}

#[derive(Clone, Copy)]
enum MemorySignal {
    Pressure(u64),
    Free(u64),
}

impl MemorySignal {
    fn pressure(self) -> Option<u64> {
        match self {
            Self::Pressure(value) => Some(value),
            Self::Free(_) => None,
        }
    }
    fn free(self) -> Option<u64> {
        match self {
            Self::Pressure(_) => None,
            Self::Free(value) => Some(value),
        }
    }
}

fn parse_memory_signal(input: &str) -> Option<MemorySignal> {
    input.lines().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        if lower.contains("memory pressure") {
            lower
                .split(|c: char| !c.is_ascii_digit())
                .find(|s| !s.is_empty())
                .and_then(|s| s.parse().ok())
                .map(MemorySignal::Pressure)
        } else if lower.contains("memory free percentage") {
            lower
                .split(|c: char| !c.is_ascii_digit())
                .find(|s| !s.is_empty())
                .and_then(|s| s.parse().ok())
                .map(MemorySignal::Free)
        } else {
            None
        }
    })
}

#[derive(Debug, Clone, Copy)]
struct SwapUsage {
    total: u64,
    used: u64,
}

fn parse_swapusage(input: &str) -> Option<SwapUsage> {
    let total = named_size(input, "total")?;
    let used = named_size(input, "used")?;
    Some(SwapUsage { total, used })
}

fn named_size(input: &str, name: &str) -> Option<u64> {
    let lower = input.to_ascii_lowercase();
    let rest = lower.split_once(&format!("{name} ="))?.1.trim_start();
    let token = rest.split_whitespace().next()?.trim_end_matches(',');
    parse_binary_size(token)
}

fn parse_binary_size(input: &str) -> Option<u64> {
    let split = input.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
    let (number, unit) = input.split_at(split);
    let multiplier = match unit.trim().to_ascii_uppercase().as_str() {
        "B" => 1.0,
        "K" | "KB" => 1024.0,
        "M" | "MB" => 1024.0 * 1024.0,
        "G" | "GB" => 1024.0 * 1024.0 * 1024.0,
        "T" | "TB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((number.parse::<f64>().ok()? * multiplier) as u64)
}

#[derive(Debug, Clone, Copy)]
struct DiskUsage {
    capacity: u64,
    used: u64,
    free: u64,
}

fn parse_diskutil_info(input: &str) -> Option<DiskUsage> {
    let value = plist::Value::from_reader_xml(input.as_bytes()).ok()?;
    let dict = value.as_dictionary()?;
    let capacity = dict.get("TotalSize")?.as_unsigned_integer()?;
    let free = dict
        .get("APFSContainerFree")
        .or_else(|| dict.get("VolumeFreeSpace"))?
        .as_unsigned_integer()?;
    Some(DiskUsage {
        capacity,
        used: capacity.saturating_sub(free),
        free,
    })
}

#[derive(Debug, Clone, Copy)]
struct MacosCapacity {
    important: u64,
}

fn parse_macos_capacity(input: &str) -> Option<MacosCapacity> {
    let value: serde_json::Value = serde_json::from_str(input.trim()).ok()?;
    let total = value.get("total")?.as_u64()?;
    let physical = value.get("physical")?.as_u64()?;
    let important = value.get("important")?.as_u64()?;
    (important >= physical && total >= important).then_some(MacosCapacity { important })
}

fn count_local_snapshots(input: &str) -> u64 {
    input
        .lines()
        .filter(|line| line.trim().starts_with("com.apple.TimeMachine."))
        .count() as u64
}

#[derive(Debug, Clone)]
struct Process {
    pid: u64,
    user: String,
    cpu: f64,
    memory_percent: f64,
    rss_bytes: u64,
    state: String,
    command: String,
}

fn parse_processes(input: &str) -> Vec<Process> {
    input
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let pid = parts.next()?.parse().ok()?;
            let user = parts.next()?.to_string();
            let cpu = parts.next()?.parse().ok()?;
            let memory_percent = parts.next()?.parse().ok()?;
            let rss_bytes = parts.next()?.parse::<u64>().ok()?.saturating_mul(1024);
            let state = parts.next()?.to_string();
            let command = parts.collect::<Vec<_>>().join(" ");
            (!command.is_empty()).then_some(Process {
                pid,
                user,
                cpu,
                memory_percent,
                rss_bytes,
                state,
                command,
            })
        })
        .collect()
}

/// Return a compact union of the top CPU and resident-memory consumers. A
/// CPU-only sort hides quiet but very large VMs and browser/agent processes;
/// a memory-only sort misses a hot compiler, so the overview intentionally
/// shows both perspectives without duplicate PIDs.
fn top_processes(processes: Vec<Process>) -> Vec<Process> {
    let mut by_cpu = processes.clone();
    by_cpu.sort_by(|a, b| {
        b.cpu
            .partial_cmp(&a.cpu)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.rss_bytes.cmp(&a.rss_bytes))
    });
    let mut by_memory = processes;
    by_memory.sort_by(|a, b| {
        b.rss_bytes.cmp(&a.rss_bytes).then_with(|| {
            b.cpu
                .partial_cmp(&a.cpu)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });
    let mut selected = BTreeMap::new();
    for process in by_cpu
        .into_iter()
        .take(PROCESS_LIMIT / 2)
        .chain(by_memory.into_iter().take(PROCESS_LIMIT / 2))
    {
        selected.insert(process.pid, process);
    }
    let mut selected: Vec<Process> = selected.into_values().collect();
    selected.sort_by(|a, b| {
        b.cpu
            .partial_cmp(&a.cpu)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.rss_bytes.cmp(&a.rss_bytes))
    });
    selected
}

fn human(bytes: u64) -> String {
    humansize::format_size(bytes, humansize::BINARY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Paths};
    use crate::model::ScanEvent;
    use crate::runner::MockCommandRunner;
    use std::sync::Arc;

    #[test]
    fn parses_load_memory_swap_and_processes() {
        assert_eq!(parse_loadavg("{ 2.00 1.50 1.25 }"), Some([2.0, 1.5, 1.25]));
        let memory = parse_vm_stat("Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages active: 10.\nPages inactive: 20.\nPages speculative: 3.\nPages wired down: 4.\nPages occupied by compressor: 5.\n").unwrap();
        assert_eq!(memory.page_size, 16384);
        assert_eq!(memory.compressed, 5);
        assert!(matches!(
            parse_memory_signal("System-wide memory free percentage: 47%"),
            Some(MemorySignal::Free(47))
        ));
        let swap = parse_swapusage("total = 4096.00M  used = 1024.00M  free = 3072.00M").unwrap();
        assert_eq!(swap.used, 1024 * 1024 * 1024);
        let processes = parse_processes(" 123 nicky 45.2 2.5 1048576 R /Applications/Chrome\n");
        assert_eq!(processes[0].rss_bytes, 1024 * 1024 * 1024);
    }

    #[test]
    fn top_processes_keeps_cpu_and_memory_outliers() {
        let processes = vec![
            Process {
                pid: 1,
                user: "u".into(),
                cpu: 90.0,
                memory_percent: 0.1,
                rss_bytes: 10,
                state: "R".into(),
                command: "hot".into(),
            },
            Process {
                pid: 2,
                user: "u".into(),
                cpu: 0.1,
                memory_percent: 50.0,
                rss_bytes: 10_000,
                state: "S".into(),
                command: "big".into(),
            },
        ];
        let selected = top_processes(processes);
        assert_eq!(selected.len(), 2);
        assert!(selected.iter().any(|p| p.command == "hot"));
        assert!(selected.iter().any(|p| p.command == "big"));
    }

    #[test]
    fn parses_diskutil_plist_and_rejects_bad_data() {
        let xml = r#"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>TotalSize</key><integer>1000</integer><key>APFSContainerFree</key><integer>250</integer></dict></plist>"#;
        let disk = parse_diskutil_info(xml).unwrap();
        assert_eq!(disk.used, 750);
        assert!(parse_diskutil_info("nope").is_none());
    }

    #[test]
    fn parses_native_macos_available_capacity() {
        let capacity =
            parse_macos_capacity(r#"{"total":1000,"physical":40,"important":330}"#).unwrap();
        assert_eq!(capacity.important, 330);
        assert!(parse_macos_capacity(r#"{"total":1000,"physical":40,"important":1200}"#).is_none());
    }

    #[test]
    fn counts_time_machine_local_snapshots_without_assuming_sizes() {
        assert_eq!(
            count_local_snapshots(
                "Snapshots for disk /:\ncom.apple.TimeMachine.2024-06-01-120000.local\nnot a snapshot\ncom.apple.TimeMachine.2024-06-02-120000.local\n"
            ),
            2
        );
    }

    #[tokio::test]
    async fn emits_ephemeral_live_data_and_durable_root_disk() {
        let disk_xml = r#"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>TotalSize</key><integer>1000</integer><key>APFSContainerFree</key><integer>250</integer></dict></plist>"#;
        let runner = MockCommandRunner::new()
            .on("sysctl", &["-n", "vm.loadavg"], "{ 2.00 1.50 1.25 }")
            .on("sysctl", &["-n", "hw.ncpu"], "8\n")
            .on("sysctl", &["-n", "hw.memsize"], "17179869184\n")
            .on("vm_stat", &[], "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages active: 10.\nPages inactive: 20.\nPages speculative: 3.\nPages wired down: 4.\nPages occupied by compressor: 5.\n")
            .on("memory_pressure", &["-Q"], "System-wide memory pressure: 10%\n")
            .on("sysctl", &["-n", "vm.swapusage"], "total = 4096.00M  used = 0.00M  free = 4096.00M")
            .on("diskutil", &["info", "-plist", "/"], disk_xml)
            .on(
                "osascript",
                &["-l", "JavaScript", "-e", VOLUME_CAPACITY_SCRIPT],
                r#"{"total":1000,"physical":250,"important":500}"#,
            )
            .on(
                "tmutil",
                &["listlocalsnapshots", "/"],
                "Snapshots for disk /:\ncom.apple.TimeMachine.2024-06-01-120000.local\ncom.apple.TimeMachine.2024-06-02-120000.local\n",
            )
            .on("ps", &["-axo", "pid=,user=,%cpu=,%mem=,rss=,state=,comm="], " 123 nicky 45.2 2.5 1048576 R /Applications/Chrome\n");
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let ctx = ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: Arc::new(Config::default()),
            paths: Arc::new(Paths::from_home("/tmp/fh")),
            runner: Arc::new(runner),
            current: ScannerId::System,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        SystemScanner.scan(ctx).await.unwrap();
        let mut findings = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = event {
                findings.push(*finding);
            }
        }
        assert!(findings.iter().any(|f| f.title == "CPU load"
            && f.snapshot_policy == crate::model::SnapshotPolicy::Ephemeral));
        let root = findings.iter().find(|f| f.title == "Root disk").unwrap();
        assert_eq!(root.snapshot_policy, crate::model::SnapshotPolicy::Durable);
        assert_eq!(root.size_bytes, Some(750));
        assert_eq!(root.meta["macos_available_bytes"], 500);
        assert_eq!(root.meta["estimated_reclaimable_bytes"], 250);
        assert_eq!(root.meta["local_time_machine_snapshot_count"], 2);
        assert!(root.detail.contains("2 local Time Machine snapshots"));
    }
}
