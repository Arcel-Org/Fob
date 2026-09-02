use tauri::State;
use uuid::Uuid;

use crate::dto::TotpCodeDto;
use crate::session::SessionState;

#[tauri::command(rename_all = "snake_case")]
pub fn totp_code(state: State<SessionState>, id: String) -> Result<TotpCodeDto, String> {
    let id = Uuid::parse_str(&id).map_err(|_| "invalid entry id".to_string())?;
    let guard = state
        .lock()
        .map_err(|_| "session lock poisoned".to_string())?;
    let session = guard
        .as_ref()
        .ok_or_else(|| "vault is locked".to_string())?;
    let entry = session
        .blob
        .totps
        .iter()
        .find(|e| e.id == id)
        .ok_or_else(|| "entry not found".to_string())?;
    let code = fob_core::totp::generate_now(entry).map_err(|e| e.to_string())?;
    let seconds_remaining =
        fob_core::totp::seconds_remaining(entry.period).map_err(|e| e.to_string())?;
    Ok(TotpCodeDto {
        code,
        seconds_remaining,
    })
}
