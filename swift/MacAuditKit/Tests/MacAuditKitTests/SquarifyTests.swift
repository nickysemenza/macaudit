import CoreGraphics
import Testing
@testable import MacAuditKit

private let bounds = CGRect(x: 0, y: 0, width: 400, height: 300)

@Test func layoutEmptyItemsReturnsEmpty() {
    #expect(Squarify.layout([], in: bounds) == [])
}

@Test func layoutZeroAreaBoundsReturnsEmpty() {
    let items = [Squarify.Item(id: "a", value: 10)]
    #expect(Squarify.layout(items, in: .zero) == [])
    #expect(Squarify.layout(items, in: CGRect(x: 0, y: 0, width: 0, height: 100)) == [])
}

@Test func layoutDropsNonPositiveValues() {
    let items = [
        Squarify.Item(id: "a", value: 10),
        Squarify.Item(id: "zero", value: 0),
        Squarify.Item(id: "negative", value: -5),
    ]
    let cells = Squarify.layout(items, in: bounds)
    #expect(cells.map(\.id) == ["a"])
}

@Test func layoutSingleItemFillsBounds() {
    let cells = Squarify.layout([Squarify.Item(id: "solo", value: 42)], in: bounds)
    #expect(cells.count == 1)
    #expect(cells[0].id == "solo")
    #expect(abs(cells[0].rect.width - bounds.width) < 0.001)
    #expect(abs(cells[0].rect.height - bounds.height) < 0.001)
}

@Test func layoutTotalAreaMatchesBounds() {
    let items = (0..<12).map { Squarify.Item(id: "\($0)", value: Double(($0 + 1) * ($0 + 1))) }
    let cells = Squarify.layout(items, in: bounds)
    let totalArea = cells.reduce(0.0) { $0 + Double($1.rect.width * $1.rect.height) }
    let boundsArea = Double(bounds.width * bounds.height)
    #expect(abs(totalArea - boundsArea) < 1.0)
}

@Test func layoutCellsStayInsideBounds() {
    let items = (0..<20).map { Squarify.Item(id: "\($0)", value: Double.random(in: 1...500)) }
    let cells = Squarify.layout(items, in: bounds)
    for cell in cells {
        #expect(cell.rect.minX >= bounds.minX - 0.5)
        #expect(cell.rect.minY >= bounds.minY - 0.5)
        #expect(cell.rect.maxX <= bounds.maxX + 0.5)
        #expect(cell.rect.maxY <= bounds.maxY + 0.5)
    }
}

@Test func layoutCellsDoNotOverlap() {
    let items = (0..<25).map { Squarify.Item(id: "\($0)", value: Double(($0 % 7) + 1) * 13) }
    let cells = Squarify.layout(items, in: bounds)
    for i in 0..<cells.count {
        for j in (i + 1)..<cells.count where j > i {
            let overlap = cells[i].rect.intersection(cells[j].rect)
            let overlapArea = overlap.isNull ? 0 : Double(overlap.width * overlap.height)
            #expect(overlapArea < 0.5, "cells \(cells[i].id) and \(cells[j].id) overlap by \(overlapArea)")
        }
    }
}

@Test func layoutAreasAreProportionalToValues() {
    let items = [
        Squarify.Item(id: "a", value: 100),
        Squarify.Item(id: "b", value: 50),
        Squarify.Item(id: "c", value: 25),
        Squarify.Item(id: "d", value: 25),
    ]
    let cells = Squarify.layout(items, in: bounds)
    let byId = Dictionary(uniqueKeysWithValues: cells.map { ($0.id, Double($0.rect.width * $0.rect.height)) })
    let totalValue = items.reduce(0.0) { $0 + $1.value }
    let boundsArea = Double(bounds.width * bounds.height)
    for item in items {
        let expected = (item.value / totalValue) * boundsArea
        let actual = byId[item.id]!
        let ratio = actual / expected
        #expect(abs(ratio - 1) < 0.02, "\(item.id): expected \(expected), got \(actual)")
    }
}

@Test func layoutHandlesManyRandomItemsQuickly() {
    let items = (0..<1000).map { Squarify.Item(id: "item-\($0)", value: Double.random(in: 1...10_000)) }
    let large = CGRect(x: 0, y: 0, width: 4000, height: 3000)
    let cells = Squarify.layout(items, in: large)
    #expect(cells.count == 1000)

    let totalArea = cells.reduce(0.0) { $0 + Double($1.rect.width * $1.rect.height) }
    let boundsArea = Double(large.width * large.height)
    #expect(abs(totalArea - boundsArea) / boundsArea < 0.001)

    for cell in cells {
        #expect(cell.rect.minX >= large.minX - 0.5)
        #expect(cell.rect.minY >= large.minY - 0.5)
        #expect(cell.rect.maxX <= large.maxX + 0.5)
        #expect(cell.rect.maxY <= large.maxY + 0.5)
    }
}
