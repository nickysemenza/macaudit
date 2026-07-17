//! Keymap: crossterm key events → semantic `Action`s.
//!
//! This layer is deliberately *mode-agnostic* — it maps raw keys (arrows,
//! Tab/BackTab, Enter/Esc/Backspace, ctrl-c, and every other char) to a small
//! `Action` enum, without deciding what a key means. That decision belongs to
//! `AppState::handle`, which interprets the same physical key differently
//! depending on its current `Mode` (Normal / Filter / Confirm) — e.g. `'q'`
//! quits in Normal mode but is ordinary filter text in Filter mode. Keeping
//! that policy out of this file is what makes the filter text box able to
//! contain any character, including ones that are single-key shortcuts
//! elsewhere.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Up,
    Down,
    Left,
    Right,
    Tab,
    BackTab,
    Enter,
    Esc,
    Backspace,
    /// Scroll the detail pane down/up (PageDown/PageUp, or ctrl-d/ctrl-u —
    /// the readline-ish aliases many terminal users reach for).
    PageDown,
    PageUp,
    /// Any printable character, including space — interpretation is
    /// mode-dependent (e.g. `' '` marks a row in Normal mode but types a
    /// space in Filter mode).
    Char(char),
    /// ctrl-c always quits, in every mode.
    CtrlC,
}

/// Map a key event to an action (`None` if unbound/unhandled, e.g. key-release
/// events on platforms that report them).
pub fn map(key: KeyEvent) -> Option<Action> {
    use Action::*;
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    Some(match key.code {
        KeyCode::Char('c') if ctrl => CtrlC,
        KeyCode::Char('d') if ctrl => PageDown,
        KeyCode::Char('u') if ctrl => PageUp,
        KeyCode::Up => Up,
        KeyCode::Down => Down,
        KeyCode::Left => Left,
        KeyCode::Right => Right,
        KeyCode::PageDown => PageDown,
        KeyCode::PageUp => PageUp,
        KeyCode::Tab => Tab,
        KeyCode::BackTab => BackTab,
        KeyCode::Enter => Enter,
        KeyCode::Esc => Esc,
        KeyCode::Backspace => Backspace,
        KeyCode::Char(c) => Char(c),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState};

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn ctrl_c_maps_distinctly_from_plain_c() {
        assert_eq!(
            map(key(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(Action::CtrlC)
        );
        assert_eq!(
            map(key(KeyCode::Char('c'), KeyModifiers::NONE)),
            Some(Action::Char('c'))
        );
    }

    #[test]
    fn every_char_passes_through_unmodified() {
        for c in ['q', 'j', 'k', 'h', 'r', 'R', 's', 'x', '/', 'y', 'n', ' '] {
            assert_eq!(
                map(key(KeyCode::Char(c), KeyModifiers::NONE)),
                Some(Action::Char(c))
            );
        }
    }

    #[test]
    fn navigation_and_control_keys_map() {
        assert_eq!(map(key(KeyCode::Up, KeyModifiers::NONE)), Some(Action::Up));
        assert_eq!(
            map(key(KeyCode::Down, KeyModifiers::NONE)),
            Some(Action::Down)
        );
        assert_eq!(
            map(key(KeyCode::Left, KeyModifiers::NONE)),
            Some(Action::Left)
        );
        assert_eq!(
            map(key(KeyCode::Right, KeyModifiers::NONE)),
            Some(Action::Right)
        );
        assert_eq!(
            map(key(KeyCode::Tab, KeyModifiers::NONE)),
            Some(Action::Tab)
        );
        assert_eq!(
            map(key(KeyCode::BackTab, KeyModifiers::NONE)),
            Some(Action::BackTab)
        );
        assert_eq!(
            map(key(KeyCode::Enter, KeyModifiers::NONE)),
            Some(Action::Enter)
        );
        assert_eq!(
            map(key(KeyCode::Esc, KeyModifiers::NONE)),
            Some(Action::Esc)
        );
        assert_eq!(
            map(key(KeyCode::Backspace, KeyModifiers::NONE)),
            Some(Action::Backspace)
        );
    }

    #[test]
    fn page_up_down_map_directly_and_via_ctrl_aliases() {
        assert_eq!(
            map(key(KeyCode::PageDown, KeyModifiers::NONE)),
            Some(Action::PageDown)
        );
        assert_eq!(
            map(key(KeyCode::PageUp, KeyModifiers::NONE)),
            Some(Action::PageUp)
        );
        assert_eq!(
            map(key(KeyCode::Char('d'), KeyModifiers::CONTROL)),
            Some(Action::PageDown)
        );
        assert_eq!(
            map(key(KeyCode::Char('u'), KeyModifiers::CONTROL)),
            Some(Action::PageUp)
        );
        // Plain (unmodified) d/u remain ordinary chars, e.g. for filter text.
        assert_eq!(
            map(key(KeyCode::Char('d'), KeyModifiers::NONE)),
            Some(Action::Char('d'))
        );
        assert_eq!(
            map(key(KeyCode::Char('u'), KeyModifiers::NONE)),
            Some(Action::Char('u'))
        );
    }
}
