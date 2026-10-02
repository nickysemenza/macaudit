import MacAuditCollections

struct PresentationCache<Key: Hashable, Value> {
    let capacity: Int
    private(set) var values: OrderedDictionary<Key, Value> = [:]

    mutating func value(for key: Key) -> Value? {
        guard let value = values.removeValue(forKey: key) else { return nil }
        values[key] = value
        return value
    }

    mutating func insert(_ value: Value, for key: Key) {
        values.removeValue(forKey: key)
        values[key] = value
        while values.count > max(0, capacity) {
            values.removeFirst()
        }
    }

    mutating func removeAll() {
        values.removeAll()
    }
}
