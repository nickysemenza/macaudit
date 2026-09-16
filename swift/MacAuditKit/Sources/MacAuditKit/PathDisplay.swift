import Foundation

/// Path formatting for the Disk tree UI: home-relative abbreviation and the
/// breadcrumb trail between a scan root and a drilled-down path.
public enum PathDisplay {
    /// "~/dev" for a path under `home`, "~" for `home` itself, unchanged
    /// otherwise.
    public static func abbreviateHome(_ path: String, home: String = NSHomeDirectory()) -> String {
        if path == home {
            return "~"
        }
        if path.hasPrefix(home + "/") {
            return "~" + path.dropFirst(home.count)
        }
        return path
    }

    /// Breadcrumb pieces from `root` down to `path`, each paired with its
    /// absolute path. `root`'s label is "~" when it is the home directory,
    /// else its last path component. A `path` outside `root` yields just its
    /// own last component (no breadcrumb trail is possible).
    public static func components(_ path: String, root: String) -> [(label: String, path: String)] {
        guard path == root || path.hasPrefix(root + "/") else {
            return [(lastComponent(path), path)]
        }
        let rootLabel = root == NSHomeDirectory() ? "~" : lastComponent(root)
        var out: [(label: String, path: String)] = [(rootLabel, root)]
        guard path != root else { return out }

        var current = root
        let suffix = path.dropFirst(root.count + 1)
        for part in suffix.split(separator: "/") {
            current += "/" + part
            out.append((String(part), current))
        }
        return out
    }

    private static func lastComponent(_ path: String) -> String {
        (path as NSString).lastPathComponent
    }
}
