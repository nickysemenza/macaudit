import CoreGraphics
import Foundation
import MacAuditKit

struct ExploreTile: Identifiable, Sendable {
    enum Kind: String, Sendable { case directory, residual }
    var id: String
    var title: String
    var bytes: UInt64
    var kind: Kind
    var rect: CGRect = .zero
}

struct ExploreScene: Sendable {
    static let tileLimit = 2048
    static let labelLimit = 128
    var tiles: [ExploreTile]
    var labels: Set<String>
    var pageMetadata: [SessionMetadata] = []

    static func build(current: DirEntry?, entries: [DirEntry],
                      incomplete: Bool, size: CGSize, pageMetadata: [SessionMetadata] = []) -> ExploreScene
    {
        guard let current, current.alloc > 0 else { return ExploreScene(tiles: [], labels: []) }
        var remaining = current.alloc
        var tiles: [ExploreTile] = []
        for entry in entries.sorted(by: { $0.alloc > $1.alloc }).prefix(tileLimit - 1) {
            let bytes = min(remaining, entry.alloc)
            guard bytes > 0 else { continue }
            tiles.append(ExploreTile(id: entry.path, title: entry.name, bytes: bytes, kind: .directory))
            remaining -= bytes
        }
        if remaining > 0 {
            let omitted = incomplete || entries.count > tileLimit - 1
            tiles.append(ExploreTile(id: "residual:\(current.path)",
                                     title: omitted ? "Other folders and direct files" : "Other direct files",
                                     bytes: remaining, kind: .residual))
        }
        let geometry = Squarify.layout(tiles.map { Squarify.Item(id: $0.id, value: Double($0.bytes)) },
                                       in: CGRect(origin: .zero, size: size))
        let rectangles = Dictionary(uniqueKeysWithValues: geometry.map { ($0.id, $0.rect) })
        tiles = tiles.map { tile in
            var tile = tile
            tile.rect = rectangles[tile.id] ?? .zero
            return tile
        }
        let labels = Set(tiles.sorted(by: { $0.bytes > $1.bytes })
            .filter { $0.rect.width >= 80 && $0.rect.height >= 34 }.prefix(labelLimit).map(\.id))
        return ExploreScene(tiles: tiles, labels: labels, pageMetadata: pageMetadata)
    }
}
