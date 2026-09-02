mod clipboard;
mod device;
mod entries;
mod recovery;
mod ssh;
mod totp;
mod vault;

pub use clipboard::*;
pub use device::*;
pub use entries::*;
pub use recovery::*;
pub use ssh::*;
pub use totp::*;
pub use vault::*;

use crate::session::Session;
use crate::session::SessionState;

/// Run `f` against the current session, or fail with a consistent "vault is
/// locked" error if none is open. The single choke point every mutating
/// command routes through.
fn with_session_mut<T>(
    state: &tauri::State<SessionState>,
    f: impl FnOnce(&mut Session) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = state
        .lock()
        .map_err(|_| "session lock poisoned".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "vault is locked".to_string())?;
    f(session)
}
