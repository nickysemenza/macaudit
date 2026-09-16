//! End-to-end: the real `macaudit` binary against a synthetic HOME that
//! mirrors the audited Mac's manager layouts (npm prefix, pnpm current +
//! legacy, cargo, pipx, uv, a Homebrew-like python site), checking the
//! `scan --json` contract, id stability across runs, and `clean --dry-run`
//! (text and JSON).
//!
//! The process `PATH` is pinned so command resolution is deterministic; the
//! login-shell probe runs `dscl`, which is not mocked here — on a machine
//! without it the scan degrades to the process PATH, which the assertions
//! tolerate. Nothing in this test touches the real machine's tools.

use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn exe(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn build_home() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().to_path_buf();
    let prefix = home.join("opt/homebrew");

    // npm prefix: leftpad (installed) + a dangling link from a removed package.
    let nm = prefix.join("lib/node_modules");
    std::fs::create_dir_all(nm.join("leftpad")).unwrap();
    std::fs::write(
        nm.join("leftpad/package.json"),
        r#"{"name":"leftpad","version":"1.3.0","bin":{"leftpad":"cli.js"}}"#,
    )
    .unwrap();
    exe(
        &nm.join("leftpad/cli.js"),
        "#!/bin/sh\necho leftpad 1.3.0\n",
    );
    std::fs::create_dir_all(prefix.join("bin")).unwrap();
    symlink(
        "../lib/node_modules/leftpad/cli.js",
        prefix.join("bin/leftpad"),
    )
    .unwrap();
    symlink("../lib/node_modules/gone/cli.js", prefix.join("bin/gone")).unwrap();
    exe(&prefix.join("bin/npm"), "#!/bin/sh\n");
    exe(&prefix.join("bin/node"), "#!/bin/sh\n");

    // pnpm: current v11 layout + legacy global/5 with a legacy-only package.
    let pnpm = home.join("Library/pnpm");
    let real = pnpm.join("global/v11/aaaa-1-0");
    std::fs::create_dir_all(real.join("node_modules/wrangler/bin")).unwrap();
    std::fs::write(
        real.join("package.json"),
        r#"{"dependencies":{"wrangler":"^4"}}"#,
    )
    .unwrap();
    std::fs::write(
        real.join("node_modules/wrangler/package.json"),
        r#"{"name":"wrangler","version":"4.131.1","bin":{"wrangler":"bin/wrangler.js"}}"#,
    )
    .unwrap();
    exe(
        &real.join("node_modules/wrangler/bin/wrangler.js"),
        "#!/bin/sh\necho wrangler\n",
    );
    symlink("aaaa-1-0", pnpm.join("global/v11/hash0000")).unwrap();
    let legacy = pnpm.join("global/5");
    std::fs::create_dir_all(legacy.join("node_modules/clawhub/dist")).unwrap();
    std::fs::write(
        legacy.join("package.json"),
        r#"{"dependencies":{"clawhub":"0.7.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        legacy.join("node_modules/clawhub/package.json"),
        r#"{"name":"clawhub","version":"0.7.0","bin":{"clawhub":"dist/cli.js"}}"#,
    )
    .unwrap();
    exe(
        &legacy.join("node_modules/clawhub/dist/cli.js"),
        "#!/bin/sh\n",
    );
    std::fs::write(
        legacy.join("node_modules/.modules.yaml"),
        format!("layoutVersion: 5\npackageManager: pnpm@10.30.0\nstoreDir: {}\nvirtualStoreDir: ../.pnpm\n", pnpm.join("store/v10").display()),
    )
    .unwrap();
    exe(
        &pnpm.join(".tools/@pnpm+macos-arm64/10.30.0/bin/pnpm"),
        "#!/bin/sh\n",
    );
    for (name, rel) in [
        (
            "wrangler",
            "../global/v11/hash0000/node_modules/wrangler/bin/wrangler.js",
        ),
        ("clawhub", "../global/5/node_modules/clawhub/dist/cli.js"),
        (
            "pnpm",
            "../global/v11/hash0000/node_modules/pnpm/bin/pnpm.cjs",
        ),
    ] {
        exe(
            &pnpm.join("bin").join(name),
            &format!("#!/bin/sh\nbasedir=$(dirname \"$0\")\nexec node \"$basedir/{rel}\" \"$@\"\n"),
        );
    }

    // cargo: one installed crate.
    let cargo = home.join(".cargo");
    std::fs::create_dir_all(cargo.join("bin")).unwrap();
    std::fs::write(
        cargo.join(".crates2.json"),
        r#"{"installs":{"wasm-pack 0.14.0 (registry+https://github.com/rust-lang/crates.io-index)":{"bins":["wasm-pack"]}}}"#,
    )
    .unwrap();
    exe(
        &cargo.join("bin/wasm-pack"),
        "#!/bin/sh\necho wasm-pack 0.14.0\n",
    );

    // pipx venv on a missing interpreter (broken) + uv tool providing the same
    // command with the live launcher (duplicate; pipx copy shadowed).
    let py = home.join("py/3.13/bin/python3.13");
    let venv = home.join(".local/pipx/venvs/mcp-proxy");
    std::fs::create_dir_all(venv.join("bin")).unwrap();
    symlink(&py, venv.join("bin/python")).unwrap();
    std::fs::write(
        venv.join("pyvenv.cfg"),
        format!("home = {}\n", py.parent().unwrap().display()),
    )
    .unwrap();
    exe(&venv.join("bin/mcp-proxy"), "#!/bin/sh\n");
    std::fs::write(
        venv.join("pipx_metadata.json"),
        format!(
            r#"{{"main_package":{{"package":"mcp-proxy","package_version":"0.11.0","apps":["mcp-proxy"],"app_paths":[{{"__Path__":"{}","__type__":"Path"}}]}},"python_version":"Python 3.13.7","source_interpreter":{{"__Path__":"{}","__type__":"Path"}}}}"#,
            venv.join("bin/mcp-proxy").display(),
            py.display()
        ),
    )
    .unwrap();
    let uv_tool = home.join(".local/share/uv/tools/mcp-proxy");
    let interp_home = prefix.join("opt/python@3.14/bin");
    exe(&interp_home.join("python3.14"), "#!/bin/sh\n");
    std::fs::create_dir_all(uv_tool.join("bin")).unwrap();
    std::fs::create_dir_all(
        uv_tool.join("lib/python3.14/site-packages/mcp_proxy-0.12.0.dist-info"),
    )
    .unwrap();
    std::fs::write(
        uv_tool.join("lib/python3.14/site-packages/mcp_proxy-0.12.0.dist-info/METADATA"),
        "Name: mcp-proxy\nVersion: 0.12.0\n\n",
    )
    .unwrap();
    symlink(interp_home.join("python3.14"), uv_tool.join("bin/python")).unwrap();
    std::fs::write(
        uv_tool.join("pyvenv.cfg"),
        format!("home = {}\nversion_info = 3.14.6\n", interp_home.display()),
    )
    .unwrap();
    exe(
        &uv_tool.join("bin/mcp-proxy"),
        "#!/bin/sh\necho mcp-proxy 0.12.0\n",
    );
    std::fs::create_dir_all(home.join(".local/bin")).unwrap();
    symlink(
        uv_tool.join("bin/mcp-proxy"),
        home.join(".local/bin/mcp-proxy"),
    )
    .unwrap();
    std::fs::write(
        uv_tool.join("uv-receipt.toml"),
        format!(
            "[tool]\nrequirements = [{{ name = \"mcp-proxy\" }}]\nentrypoints = [\n  {{ name = \"mcp-proxy\", install-path = \"{}\", from = \"mcp-proxy\" }},\n  {{ name = \"mcp-reverse-proxy\", install-path = \"{}\", from = \"mcp-proxy\" }},\n]\n",
            home.join(".local/bin/mcp-proxy").display(),
            home.join(".local/bin/mcp-reverse-proxy").display()
        ),
    )
    .unwrap();

    // Homebrew python site: brew-owned certifi (Cellar links) + pip requests.
    let site = prefix.join("lib/python3.14/site-packages");
    let cellar = prefix
        .join("Cellar/certifi/2026.7.22/lib/python3.14/site-packages/certifi-2026.7.22.dist-info");
    std::fs::create_dir_all(&cellar).unwrap();
    std::fs::write(
        cellar.join("METADATA"),
        "Name: certifi\nVersion: 2026.7.22\n\n",
    )
    .unwrap();
    std::fs::write(cellar.join("INSTALLER"), "brew").unwrap();
    std::fs::create_dir_all(site.join("certifi-2026.7.22.dist-info")).unwrap();
    symlink(
        cellar.join("METADATA"),
        site.join("certifi-2026.7.22.dist-info/METADATA"),
    )
    .unwrap();
    symlink(
        cellar.join("INSTALLER"),
        site.join("certifi-2026.7.22.dist-info/INSTALLER"),
    )
    .unwrap();
    let req = site.join("requests-2.32.5.dist-info");
    std::fs::create_dir_all(&req).unwrap();
    std::fs::write(
        req.join("METADATA"),
        "Name: requests\nVersion: 2.32.5\nRequires-Dist: certifi\n\n",
    )
    .unwrap();
    std::fs::write(req.join("INSTALLER"), "pip").unwrap();
    std::fs::write(req.join("RECORD"), "requests/__init__.py,sha256=x,120\n").unwrap();

    // Config: point the Homebrew prefix at the fixture, keep projects local.
    std::fs::create_dir_all(home.join(".config/macaudit")).unwrap();
    std::fs::write(
        home.join(".config/macaudit/config.toml"),
        format!(
            "[tools]\nhomebrew_prefix = \"{}\"\ninclude_apple_python = false\nproject_roots = [\"{}\"]\n",
            prefix.display(),
            home.join("dev").display()
        ),
    )
    .unwrap();
    std::fs::create_dir_all(home.join("dev")).unwrap();
    (tmp, prefix)
}

fn run(home: &Path, prefix: &Path, args: &[&str]) -> std::process::Output {
    let path = format!(
        "{}:{}:{}:/usr/bin:/bin",
        home.join(".local/bin").display(),
        prefix.join("bin").display(),
        home.join(".cargo/bin").display()
    );
    Command::new(env!("CARGO_BIN_EXE_macaudit"))
        .args(args)
        .env("MACAUDIT_HOME", home)
        .env("PATH", path)
        .env("SHELL", "/bin/sh") // unsupported login shell ⇒ process PATH only
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .output()
        .expect("run macaudit")
}

fn json_out(out: &std::process::Output) -> Value {
    assert!(
        out.status.success(),
        "macaudit exited {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("json")
}

fn by_title<'a>(arr: &'a [Value], kind: &str, title: &str) -> &'a Value {
    arr.iter()
        .find(|f| f["kind"] == kind && f["title"] == title)
        .unwrap_or_else(|| panic!("no {kind} finding titled {title}"))
}

#[test]
fn tools_scan_dry_run_end_to_end() {
    let (tmp, prefix) = build_home();
    let home = tmp.path();

    let first = json_out(&run(
        home,
        &prefix,
        &["scan", "--section", "tools", "--json", "--offline"],
    ));
    let arr = first.as_array().unwrap();
    let tools: Vec<&Value> = arr.iter().filter(|f| f["kind"] == "global_tool").collect();
    assert!(tools.len() >= 8, "{}", tools.len());

    let leftpad = by_title(arr, "global_tool", "leftpad");
    assert_eq!(leftpad["meta"]["manager"], "npm");
    assert_eq!(leftpad["meta"]["version"], "1.3.0");
    assert_eq!(
        leftpad["meta"]["resolution"]["leftpad"]["status"],
        "active_in_process_only"
    );
    assert_eq!(
        leftpad["meta"]["identity_key"],
        format!("npm:{}:leftpad", prefix.join("lib/node_modules").display())
    );

    // Removed package with a dangling launcher: version unknown, broken,
    // launcher-only removal is the primary action.
    let gone = by_title(arr, "global_tool", "gone");
    assert!(gone["meta"]["version"].is_null());
    assert_eq!(gone["meta"]["primary_classification"], "broken");
    assert_eq!(gone["remedies"][0]["command"]["type"], "trash");
    assert_eq!(gone["remedies"][0]["alternative"], false);
    assert_eq!(gone["remedies"][0]["guard"]["kind"], "launcher");
    assert_eq!(gone["remedies"][0]["guard"]["expect_dangling"], true);

    // Both pnpm layouts are distinct installations.
    let claw = by_title(arr, "global_tool", "clawhub");
    assert_eq!(claw["meta"]["layout"], "legacy-5", "{claw:#}");
    assert!(!claw["remedies"].as_array().unwrap().is_empty(), "{claw:#}");
    let claw_args: Vec<&str> = claw["remedies"][0]["command"]["args"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a.as_str())
        .collect();
    assert!(claw_args.contains(&"--global-dir"), "{claw_args:?}");
    assert!(claw["remedies"][0]["command"]["program"]
        .as_str()
        .unwrap()
        .ends_with(".tools/@pnpm+macos-arm64/10.30.0/bin/pnpm"));
    let wr = by_title(arr, "global_tool", "wrangler");
    assert_eq!(wr["meta"]["layout"], "v11");
    assert!(wr["meta"]["root"].as_str().unwrap().ends_with("hash0000"));

    // pipx copy broken (interpreter missing) and shadowed by uv's launcher;
    // uv copy active, duplicate, with the missing entrypoint note.
    let pipx_mp = arr
        .iter()
        .find(|f| {
            f["kind"] == "global_tool"
                && f["title"] == "mcp-proxy"
                && f["meta"]["manager"] == "pipx"
        })
        .unwrap();
    assert_eq!(pipx_mp["meta"]["primary_classification"], "broken");
    assert_eq!(
        pipx_mp["meta"]["resolution"]["mcp-proxy"]["status"],
        "shadowed"
    );
    assert_eq!(
        pipx_mp["meta"]["foreign_launchers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let uv_mp = arr
        .iter()
        .find(|f| {
            f["kind"] == "global_tool" && f["title"] == "mcp-proxy" && f["meta"]["manager"] == "uv"
        })
        .unwrap();
    assert!(uv_mp["meta"]["classifications"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["kind"] == "duplicate"));
    assert_eq!(
        uv_mp["meta"]["manager_extra"]["entrypoints_missing"][0],
        "mcp-reverse-proxy"
    );
    assert!(uv_mp["meta"]["removal"]["follow_up"][0]
        .as_str()
        .unwrap()
        .contains("may recreate"));

    // Python site ownership.
    let certifi = by_title(arr, "global_tool", "certifi");
    assert_eq!(certifi["meta"]["manager_extra"]["installer"], "brew");
    assert!(certifi["meta"]["protected"]
        .as_str()
        .unwrap()
        .contains("certifi"));
    assert!(certifi["remedies"].as_array().unwrap().is_empty());
    let requests = by_title(arr, "global_tool", "requests");
    let req_args: Vec<&str> = requests["remedies"][0]["command"]["args"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a.as_str())
        .collect();
    assert!(
        req_args.ends_with(&["--break-system-packages", "requests"]),
        "{req_args:?}"
    );
    assert_eq!(requests["remedies"][0]["guard"]["kind"], "pip_package");

    // Command resolution + coverage rows exist.
    assert!(arr
        .iter()
        .any(|f| f["kind"] == "command_resolution" && f["title"] == "wasm-pack"));
    let cov = arr.iter().find(|f| f["kind"] == "tool_coverage").unwrap();
    assert_eq!(cov["meta"]["managers"]["bun"]["status"], "absent");
    assert_eq!(cov["meta"]["managers"]["cargo"]["status"], "ok");

    // Ids are stable across runs.
    let second = json_out(&run(
        home,
        &prefix,
        &["scan", "--section", "tools", "--json", "--offline"],
    ));
    let ids = |v: &Value| -> Vec<String> {
        let mut v: Vec<String> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["id"].to_string())
            .collect();
        v.sort();
        v
    };
    assert_eq!(ids(&first), ids(&second));

    // Dry run: only evidence-backed rows by default; --select for the rest.
    let dry = run(
        home,
        &prefix,
        &["clean", "--dry-run", "--section", "tools", "--offline"],
    );
    let text = String::from_utf8_lossy(&dry.stdout);
    assert!(
        text.contains(&format!("trash {}", prefix.join("bin/gone").display())),
        "{text}"
    );
    assert!(
        !text.contains("wasm-pack"),
        "review-only rows must not be listed: {text}"
    );
    let key = format!("cargo:{}:wasm-pack", home.join(".cargo").display());
    let dry = run(
        home,
        &prefix,
        &[
            "clean",
            "--dry-run",
            "--section",
            "tools",
            "--select",
            &key,
            "--offline",
        ],
    );
    let text = String::from_utf8_lossy(&dry.stdout);
    assert!(text.contains("cargo uninstall wasm-pack --root"), "{text}");
    let dry_json = json_out(&run(
        home,
        &prefix,
        &[
            "clean",
            "--dry-run",
            "--section",
            "tools",
            "--select",
            &key,
            "--json",
            "--offline",
        ],
    ));
    assert_eq!(dry_json["actions"][0]["title"], "wasm-pack");
    assert!(dry_json["refused"].as_array().unwrap().is_empty());

    // `tools` table and `tools verify` (explicit probes of the fixture scripts).
    let table = run(home, &prefix, &["tools", "--offline"]);
    assert!(String::from_utf8_lossy(&table.stdout).contains("leftpad"));
    let verify = json_out(&run(
        home,
        &prefix,
        &["tools", "verify", "--json", "--offline"],
    ));
    let probes = verify.as_array().unwrap();
    assert!(
        probes
            .iter()
            .any(|p| p["command"] == "wasm-pack" && p["status"] == "ok"),
        "{verify:#}"
    );

    // `brew why` on the (unavailable) Homebrew of this sandbox errors cleanly.
    let why = run(home, &prefix, &["brew", "why", "nope", "--offline"]);
    assert!(!why.status.success());
    assert!(String::from_utf8_lossy(&why.stderr).contains("unknown or ambiguous"));
}
