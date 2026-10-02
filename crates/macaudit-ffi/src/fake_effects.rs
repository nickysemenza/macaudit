pub struct FakeEffects;

impl macaudit::remedy::TrashOps for FakeEffects {
    fn trash(&self, _: &std::path::Path) -> anyhow::Result<()> {
        anyhow::bail!("fake mode refuses filesystem cleanup")
    }
}

impl macaudit::remedy::ClipboardOps for FakeEffects {
    fn copy(&self, _: &str) -> anyhow::Result<()> {
        anyhow::bail!("fake mode refuses clipboard changes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use macaudit::remedy::{ClipboardOps, TrashOps};

    #[test]
    fn fake_effects_refuse_trash_and_clipboard_without_changes() {
        let home = tempfile::tempdir().unwrap();
        let target = home.path().join("retained");
        std::fs::write(&target, "retained").unwrap();
        assert!(FakeEffects.trash(&target).is_err());
        assert!(FakeEffects.copy("not copied").is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "retained");
    }
}
