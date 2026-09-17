//! App-axis owner discovery: `.app` bundles (three well-known dirs, nested
//! helper bundles folded into their outermost app), Homebrew formulae +
//! Homebrew itself, and global dev tools — joined to every `~/Library/*`,
//! dotdir, cache and data location that belongs to them.

pub mod candidates;
pub mod curated;
pub mod entitlements;
pub mod linkers;
pub mod owners;

use std::path::Path;

use super::model::{Claim, EvidenceTier, Owner, OwnerKind, ResolveEnv};

/// Run the whole App Storage resolve pass: discover owners, fetch
/// entitlements for the app owners (batched, cached), enumerate every
/// candidate path, link each to an owner (or `UNATTRIBUTED_OWNER`), and add
/// the well-known Apple data-location claims on top. Returns the owner
/// registry alongside the claims so `accounting::account` can give every
/// owner a row, even one nothing linked to.
pub fn resolve(env: &ResolveEnv<'_>) -> (Vec<Owner>, Vec<Claim>) {
    let discovered = owners::discover(env);
    let app_paths: Vec<&Path> = discovered
        .apps
        .iter()
        .filter_map(|a| a.owner.path.as_deref())
        .collect();
    let groups = entitlements::app_groups_for(env, &app_paths);
    let candidate_list = candidates::collect(env);

    let mut claims = linkers::link(env, &discovered, &candidate_list, &groups);

    // The Apple data-location table already knows its owning bundle id, so
    // these skip the tiered linker entirely. `accounting::account` derives
    // a Footprint row from the claim's owner key alone
    // (`accounting::owner_from_key`), so this works even for a bundle id
    // that `owners::discover` never produced (Finder's data — iCloud Drive —
    // is attributed to `com.apple.finder`, but Finder.app itself lives
    // under the excluded `/System/Library/CoreServices`, so it's never a
    // discovered owner; a Photos/CloudStorage-provider bundle id may not be
    // an owner either, if the app itself isn't currently installed).
    for (path, bundle_id, kind, label) in candidates::apple_data(env) {
        claims.push(
            Claim::new(
                path,
                bundle_id,
                kind,
                EvidenceTier::Exact,
                "well-known data location",
            )
            .label(label),
        );
    }

    let mut owners = discovered.into_owners();
    // Apple data locations name owners that may not be installed apps
    // (Finder never is): register them so their rows get a real name.
    for (_, bundle_id, _, _) in candidates::apple_data(env) {
        if owners.iter().any(|o| o.key == bundle_id) {
            continue;
        }
        let Some(name) = curated::apple_owner_name(bundle_id) else {
            continue;
        };
        owners.push(Owner {
            key: bundle_id.to_string(),
            kind: OwnerKind::App,
            name: name.to_string(),
            path: None,
        });
    }
    (owners, claims)
}
