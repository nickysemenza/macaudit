//! Keymap: crossterm key events → semantic `Action`s. Lane U extends this with
//! the full keybinding set; the skeleton wires navigation, marking, rescan, quit.
//!
//! Per spec §4: arrows/jk navigate rows, Tab/arrows switch sections, `space`
//! marks, `enter` opens detail, `x` executes, `r`/`R` rescan, `/` filters,
//! `s` cycles sort, `h` toggles System apps, `q` quits.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Quit,
    Up,
    Down,
    NextSection,
    PrevSection,
    Mark,
    Detail,
    RescanSection,
    RescanAll,
    Filter,
    CycleSort,
    ToggleSystem,
    Execute,
}

/// Map a key event to an action (`None` if unbound).
pub fn map(key: KeyEvent) -> Option<Action> {
    use Action::*;
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    Some(match key.code {
        KeyCode::Char('q') => Quit,
        KeyCode::Char('c') if ctrl => Quit,
        KeyCode::Up | KeyCode::Char('k') => Up,
        KeyCode::Down | KeyCode::Char('j') => Down,
        KeyCode::Tab | KeyCode::Right => NextSection,
        KeyCode::BackTab | KeyCode::Left => PrevSection,
        KeyCode::Char(' ') => Mark,
        KeyCode::Enter => Detail,
        KeyCode::Char('r') => RescanSection,
        KeyCode::Char('R') => RescanAll,
        KeyCode::Char('/') => Filter,
        KeyCode::Char('s') => CycleSort,
        KeyCode::Char('h') => ToggleSystem,
        KeyCode::Char('x') => Execute,
        _ => return None,
    })
}
