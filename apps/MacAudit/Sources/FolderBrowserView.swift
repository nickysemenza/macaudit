import SwiftUI

struct FolderBrowserView: View {
    @Environment(AuditStore.self) private var store

    var body: some View {
        ExploreView(store: store)
    }
}
