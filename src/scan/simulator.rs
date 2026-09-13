//! SimulatorScanner (spec §3.10) — `xcrun simctl list devices -j` and
//! `xcrun simctl list runtimes -j` → one finding per device and per runtime.
//! Unavailable/legacy runtimes are Reclaimable with a destructive, per-
//! identifier `xcrun simctl runtime delete <id>` remedy (NOT `simctl delete
//! unavailable`, which deletes devices). If xcrun/simctl is absent, emit
//! a single Info finding and return Ok.

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::Value;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct SimulatorScanner;

#[async_trait]
impl Scanner for SimulatorScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Simulator
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        let devices_out = match ctx
            .runner
            .run("xcrun", &["simctl", "list", "devices", "-j"], &ctx.token)
            .await
        {
            Ok(o) if o.success() => o,
            _ => {
                emit_unavailable(&ctx).await;
                return Ok(());
            }
        };
        let runtimes_out = match ctx
            .runner
            .run("xcrun", &["simctl", "list", "runtimes", "-j"], &ctx.token)
            .await
        {
            Ok(o) if o.success() => o,
            _ => {
                emit_unavailable(&ctx).await;
                return Ok(());
            }
        };

        // Build a lookup of runtime identifier -> display name, used to
        // enrich device titles.
        let mut runtime_names: HashMap<String, String> = HashMap::new();
        let runtimes_json: Value =
            serde_json::from_str(&runtimes_out.stdout_str()).unwrap_or(Value::Null);
        let runtime_list = runtimes_json
            .get("runtimes")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        for rt in &runtime_list {
            let identifier = rt.get("identifier").and_then(|v| v.as_str()).unwrap_or("");
            let name = rt
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(identifier);
            runtime_names.insert(identifier.to_string(), name.to_string());

            let version = rt.get("version").and_then(|v| v.as_str()).unwrap_or("");
            let build = rt
                .get("buildversion")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let available = is_available(rt);

            let title = if build.is_empty() {
                name.to_string()
            } else {
                format!("{name} (build {build})")
            };

            let mut finding = Finding::new(FindingKind::Simulator, identifier, title)
                .detail(format!(
                    "runtime {identifier}, version {version}, {}",
                    if available {
                        "available"
                    } else {
                        "unavailable"
                    }
                ))
                .severity(if available {
                    Severity::Info
                } else {
                    Severity::Reclaimable
                })
                .meta(serde_json::json!({
                    "kind": "runtime",
                    "identifier": identifier,
                    "version": version,
                    "build": build,
                    "available": available,
                }));

            if !available {
                // `simctl delete unavailable` deletes DEVICES, not runtimes —
                // runtime deletion is its own subcommand, targeted by identifier
                // so selecting several runtime findings runs distinct commands.
                finding = finding.remedy(Remedy {
                    label: "Delete this runtime".to_string(),
                    command: RemedyCommand::Shell {
                        program: "xcrun".to_string(),
                        args: vec![
                            "simctl".to_string(),
                            "runtime".to_string(),
                            "delete".to_string(),
                            identifier.to_string(),
                        ],
                    },
                    reclaims_bytes: None,
                    destructive: true,
                    alternative: false,
                    guard: None,
                });
            }

            ctx.emit(finding).await;
        }

        let devices_json: Value =
            serde_json::from_str(&devices_out.stdout_str()).unwrap_or(Value::Null);
        let devices_map = devices_json
            .get("devices")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        for (runtime_id, device_list) in &devices_map {
            let Some(device_list) = device_list.as_array() else {
                continue;
            };
            let runtime_name = runtime_names
                .get(runtime_id)
                .cloned()
                .unwrap_or_else(|| runtime_id.clone());

            for dev in device_list {
                let Some(udid) = dev.get("udid").and_then(|v| v.as_str()) else {
                    continue;
                };
                let name = dev.get("name").and_then(|v| v.as_str()).unwrap_or(udid);
                let state = dev
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");
                let available = is_available(dev);
                let size_bytes = dev.get("dataPathSize").and_then(|v| v.as_u64());

                let title = format!("{name} — {runtime_name}");
                let mut finding = Finding::new(FindingKind::Simulator, udid, title)
                    .detail(format!("{state}, udid {udid}"))
                    .severity(if available {
                        Severity::Info
                    } else {
                        Severity::Attention
                    })
                    .meta(serde_json::json!({
                        "kind": "device",
                        "udid": udid,
                        "runtime": runtime_id,
                        "state": state,
                        "available": available,
                    }));

                if let Some(bytes) = size_bytes {
                    finding = finding.size(bytes);
                }
                // Offer a targeted per-device delete (never the global `delete
                // unavailable`, which would act far beyond this finding) whenever
                // the device is safely deletable: unavailable, or available but
                // shut down (a duplicate device across old runtimes). A *booted*
                // device is in use, so it gets no remedy. Unavailable devices are
                // pure cruft → Reclaimable; a shut-down-but-available device may
                // still be wanted → stays Attention (actionable, not suggested).
                let deletable = !available || state == "Shutdown";
                if deletable {
                    if !available {
                        finding = finding.severity(Severity::Reclaimable);
                    }
                    finding = finding.remedy(Remedy {
                        label: "Delete this simulator device".to_string(),
                        command: RemedyCommand::Shell {
                            program: "xcrun".to_string(),
                            args: vec![
                                "simctl".to_string(),
                                "delete".to_string(),
                                udid.to_string(),
                            ],
                        },
                        reclaims_bytes: size_bytes,
                        destructive: true,
                        alternative: false,
                        guard: None,
                    });
                }

                ctx.emit(finding).await;
            }
        }

        Ok(())
    }
}

/// Accepts either the modern boolean `isAvailable` field or the legacy
/// `availability` string (`"(available)"` / `"(unavailable, ...)"`).
fn is_available(v: &Value) -> bool {
    if let Some(b) = v.get("isAvailable").and_then(|x| x.as_bool()) {
        return b;
    }
    if let Some(s) = v.get("availability").and_then(|x| x.as_str()) {
        return s.contains("available") && !s.contains("unavailable");
    }
    true
}

async fn emit_unavailable(ctx: &ScanCtx) {
    ctx.emit(
        Finding::new(
            FindingKind::Simulator,
            "simulator:unavailable",
            "xcrun/simctl not available",
        )
        .detail("Xcode command line tools are not installed or simctl failed")
        .severity(Severity::Info),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanEvent;
    use crate::runner::MockCommandRunner;

    const DEVICES_FIXTURE: &str = r#"{
  "devices": {
    "com.apple.CoreSimulator.SimRuntime.iOS-17-0": [
      {
        "dataPath": "/Users/x/Library/Developer/CoreSimulator/Devices/AAAA",
        "dataPathSize": 4294967296,
        "logPath": "/Users/x/Library/Logs/CoreSimulator/AAAA",
        "udid": "AAAA-1111",
        "isAvailable": true,
        "deviceTypeIdentifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-15",
        "state": "Shutdown",
        "name": "iPhone 15"
      }
    ],
    "com.apple.CoreSimulator.SimRuntime.iOS-15-0": [
      {
        "dataPath": "/Users/x/Library/Developer/CoreSimulator/Devices/BBBB",
        "dataPathSize": 1073741824,
        "logPath": "/Users/x/Library/Logs/CoreSimulator/BBBB",
        "udid": "BBBB-2222",
        "isAvailable": false,
        "deviceTypeIdentifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-13",
        "state": "Shutdown",
        "name": "iPhone 13"
      }
    ]
  }
}"#;

    const RUNTIMES_FIXTURE: &str = r#"{
  "runtimes": [
    {
      "bundlePath": "/Library/Developer/CoreSimulator/Volumes/iOS_21A328/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 17.0.simruntime",
      "buildversion": "21A328",
      "runtimeRoot": "/Library/Developer/CoreSimulator/Volumes/iOS_21A328",
      "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-17-0",
      "version": "17.0",
      "isAvailable": true,
      "name": "iOS 17.0",
      "supportedDeviceTypes": []
    },
    {
      "bundlePath": "/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 15.0.simruntime",
      "buildversion": "19A339",
      "runtimeRoot": "/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 15.0.simruntime",
      "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-15-0",
      "version": "15.0",
      "isAvailable": false,
      "name": "iOS 15.0",
      "supportedDeviceTypes": []
    }
  ]
}"#;

    fn ctx_with(mock: MockCommandRunner, tx: tokio::sync::mpsc::Sender<ScanEvent>) -> ScanCtx {
        ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: std::sync::Arc::new(crate::config::Config::default()),
            paths: std::sync::Arc::new(crate::config::Paths::from_home("/tmp/fh")),
            runner: std::sync::Arc::new(mock),
            current: crate::model::ScannerId::Simulator,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        }
    }

    #[tokio::test]
    async fn parses_devices_and_runtimes() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mock = MockCommandRunner::new()
            .on(
                "xcrun",
                &["simctl", "list", "devices", "-j"],
                DEVICES_FIXTURE,
            )
            .on(
                "xcrun",
                &["simctl", "list", "runtimes", "-j"],
                RUNTIMES_FIXTURE,
            );
        let ctx = ctx_with(mock, tx);
        SimulatorScanner.scan(ctx).await.unwrap();

        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        // 2 runtimes + 2 devices
        assert_eq!(findings.len(), 4);

        let unavailable_runtime = findings
            .iter()
            .find(|f| {
                f.meta["kind"] == "runtime"
                    && f.meta["identifier"] == "com.apple.CoreSimulator.SimRuntime.iOS-15-0"
            })
            .unwrap();
        assert_eq!(unavailable_runtime.severity, Severity::Reclaimable);
        assert_eq!(unavailable_runtime.remedies.len(), 1);
        assert!(unavailable_runtime.remedies[0].destructive);
        assert_eq!(
            unavailable_runtime.remedies[0].command,
            RemedyCommand::Shell {
                program: "xcrun".into(),
                args: vec![
                    "simctl".into(),
                    "runtime".into(),
                    "delete".into(),
                    "com.apple.CoreSimulator.SimRuntime.iOS-15-0".into()
                ],
            }
        );

        let available_runtime = findings
            .iter()
            .find(|f| {
                f.meta["kind"] == "runtime"
                    && f.meta["identifier"] == "com.apple.CoreSimulator.SimRuntime.iOS-17-0"
            })
            .unwrap();
        assert_eq!(available_runtime.severity, Severity::Info);
        assert!(available_runtime.remedies.is_empty());

        let device = findings
            .iter()
            .find(|f| f.meta["kind"] == "device" && f.meta["udid"] == "AAAA-1111")
            .unwrap();
        assert_eq!(device.title, "iPhone 15 — iOS 17.0");
        assert_eq!(device.size_bytes, Some(4_294_967_296));
        // Available but Shutdown: a deletable duplicate. Severity stays Info
        // (may still be wanted) but it now carries a targeted per-udid delete.
        assert_eq!(device.severity, Severity::Info);
        assert_eq!(
            device.remedies[0].command,
            RemedyCommand::Shell {
                program: "xcrun".into(),
                args: vec!["simctl".into(), "delete".into(), "AAAA-1111".into()],
            }
        );
        assert!(device.remedies[0].destructive);

        let unavailable_device = findings
            .iter()
            .find(|f| f.meta["kind"] == "device" && f.meta["udid"] == "BBBB-2222")
            .unwrap();
        // Unavailable devices are reclaimable via a TARGETED per-udid delete —
        // never the global `simctl delete unavailable`.
        assert_eq!(unavailable_device.severity, Severity::Reclaimable);
        assert_eq!(
            unavailable_device.remedies[0].command,
            RemedyCommand::Shell {
                program: "xcrun".into(),
                args: vec!["simctl".into(), "delete".into(), "BBBB-2222".into()],
            }
        );
    }

    #[tokio::test]
    async fn booted_device_gets_no_delete_remedy() {
        // A booted device is in use — it must never be offered a delete, even
        // though it's available.
        const BOOTED: &str = r#"{
  "devices": {
    "com.apple.CoreSimulator.SimRuntime.iOS-17-0": [
      {
        "dataPathSize": 2147483648,
        "udid": "CCCC-3333",
        "isAvailable": true,
        "state": "Booted",
        "name": "iPhone 15 Pro"
      }
    ]
  }
}"#;
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mock = MockCommandRunner::new()
            .on("xcrun", &["simctl", "list", "devices", "-j"], BOOTED)
            .on(
                "xcrun",
                &["simctl", "list", "runtimes", "-j"],
                r#"{"runtimes":[]}"#,
            );
        let ctx = ctx_with(mock, tx);
        SimulatorScanner.scan(ctx).await.unwrap();

        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        let device = findings
            .iter()
            .find(|f| f.meta["udid"] == "CCCC-3333")
            .unwrap();
        assert!(device.remedies.is_empty());
    }

    #[tokio::test]
    async fn missing_xcrun_emits_single_info_finding() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mock = MockCommandRunner::new();
        let ctx = ctx_with(mock, tx);
        SimulatorScanner.scan(ctx).await.unwrap();

        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }
}
