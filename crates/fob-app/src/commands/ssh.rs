use tauri::State;

use crate::session::SessionState;

/// The running SSH agent's socket path, if any keys are loaded — shown in
/// the SSH Keys view so the user can point `SSH_AUTH_SOCK` at it.
#[tauri::command(rename_all = "snake_case")]
pub fn ssh_agent_status(state: State<SessionState>) -> Option<String> {
    let guard = state.lock().ok()?;
    let session = guard.as_ref()?;
    session
        .ssh_agent
        .as_ref()
        .map(|h| h.socket_path().display().to_string())
}
