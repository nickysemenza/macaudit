mod dependencies;
mod metadata;
mod notices;

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const USAGE: &str = "Usage: macaudit-devtools target-directory
       macaudit-devtools check-dependencies [--licenses]
       macaudit-devtools third-party-notices OUTPUT [--swift-checkouts PATH ...]";

#[derive(Debug, PartialEq)]
enum Operation {
    Help,
    TargetDirectory,
    CheckDependencies {
        licenses: bool,
    },
    ThirdPartyNotices {
        output: PathBuf,
        swift_checkouts: Vec<PathBuf>,
    },
}

fn parse_arguments(arguments: impl IntoIterator<Item = OsString>) -> Result<Operation> {
    let mut arguments = arguments.into_iter();
    let subcommand = arguments.next().ok_or(USAGE)?;
    let remaining: Vec<_> = arguments.collect();
    if subcommand == "--help" || subcommand == "-h" {
        return Ok(Operation::Help);
    }
    if !matches!(
        subcommand.to_str(),
        Some("target-directory" | "check-dependencies" | "third-party-notices")
    ) {
        return Err(format!(
            "Unknown subcommand: {}\n{USAGE}",
            subcommand.to_string_lossy()
        )
        .into());
    }
    if remaining
        .iter()
        .any(|value| value == "--help" || value == "-h")
    {
        return Ok(Operation::Help);
    }
    if subcommand == "target-directory" && remaining.is_empty() {
        return Ok(Operation::TargetDirectory);
    }
    if subcommand == "check-dependencies" && remaining.iter().all(|value| value == "--licenses") {
        return Ok(Operation::CheckDependencies {
            licenses: !remaining.is_empty(),
        });
    }
    if subcommand != "third-party-notices" {
        return Err(format!(
            "Unexpected arguments for {}\n{USAGE}",
            subcommand.to_string_lossy()
        )
        .into());
    }
    let mut output = None;
    let mut swift_checkouts = Vec::new();
    let mut positional_only = false;
    let mut remaining = remaining.into_iter();
    while let Some(argument) = remaining.next() {
        if !positional_only && argument == "--" {
            positional_only = true;
        } else if !positional_only && argument == "--swift-checkouts" {
            let checkout = remaining
                .next()
                .ok_or("--swift-checkouts requires a path")?;
            if checkout.to_string_lossy().starts_with('-') && checkout != "-" {
                return Err("--swift-checkouts requires a path".into());
            }
            swift_checkouts.push(PathBuf::from(checkout));
        } else if !positional_only
            && argument
                .to_str()
                .is_some_and(|value| value.starts_with("--swift-checkouts="))
        {
            swift_checkouts.push(PathBuf::from(
                argument
                    .to_str()
                    .unwrap()
                    .trim_start_matches("--swift-checkouts="),
            ));
        } else if !positional_only && argument.to_string_lossy().starts_with('-') && argument != "-"
        {
            return Err(
                format!("Unknown argument: {}\n{USAGE}", argument.to_string_lossy()).into(),
            );
        } else if output.replace(PathBuf::from(argument)).is_some() {
            return Err(
                format!("third-party-notices requires exactly one output path\n{USAGE}").into(),
            );
        }
    }
    Ok(Operation::ThirdPartyNotices {
        output: output.ok_or("third-party-notices requires an output path")?,
        swift_checkouts,
    })
}

fn run(root: &Path, operation: Operation) -> Result<()> {
    match operation {
        Operation::Help => println!("{USAGE}"),
        Operation::TargetDirectory => println!("{}", metadata::target_directory(root)?.display()),
        Operation::CheckDependencies { licenses } => {
            let metadata = metadata::load(root)?;
            let report = dependencies::check(&metadata, licenses)?;
            print!("{}", report.output);
            if !report.failures.is_empty() {
                return Err(report.failures.join("\n").into());
            }
        }
        Operation::ThirdPartyNotices {
            output,
            swift_checkouts,
        } => {
            let metadata = metadata::load(root)?;
            notices::write(root, &metadata, &output, &swift_checkouts)?;
            println!(
                "Preserved third-party license texts in {}",
                output.display()
            );
        }
    }
    Ok(())
}

fn main() {
    let result = parse_arguments(env::args_os().skip(1)).and_then(|operation| {
        run(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
            operation,
        )
    });
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<Operation> {
        parse_arguments(arguments.iter().map(OsString::from))
    }

    #[test]
    fn parses_subcommands_and_repeated_checkout_paths() {
        assert_eq!(
            parse(&["target-directory"]).unwrap(),
            Operation::TargetDirectory
        );
        assert_eq!(
            parse(&["check-dependencies", "--licenses"]).unwrap(),
            Operation::CheckDependencies { licenses: true }
        );
        assert_eq!(
            parse(&[
                "third-party-notices",
                "--swift-checkouts",
                "first checkout",
                "notices.txt",
                "--swift-checkouts=second",
            ])
            .unwrap(),
            Operation::ThirdPartyNotices {
                output: PathBuf::from("notices.txt"),
                swift_checkouts: vec![PathBuf::from("first checkout"), PathBuf::from("second")],
            }
        );
    }

    #[test]
    fn rejects_missing_and_unknown_arguments() {
        for arguments in [
            vec![],
            vec!["unknown"],
            vec!["target-directory", "extra"],
            vec!["check-dependencies", "--unknown"],
            vec!["third-party-notices"],
            vec!["third-party-notices", "output", "second-output"],
            vec!["third-party-notices", "output", "--swift-checkouts"],
            vec![
                "third-party-notices",
                "output",
                "--swift-checkouts",
                "--unknown",
            ],
        ] {
            assert!(parse(&arguments).is_err(), "{arguments:?}");
        }
    }
}
