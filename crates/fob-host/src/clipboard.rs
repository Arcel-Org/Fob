/// Clipboard copy with a timed auto-clear, mirroring the browser vault's
/// "clears 30 seconds after any copy" behavior (see README's threat model).
pub const CLEAR_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

pub fn copy(text: &str) -> anyhow::Result<()> {
    let mut ctx = arboard::Clipboard::new()?;
    ctx.set_text(text)?;
    Ok(())
}

/// Clear the clipboard, but only if it still holds what we put there —
/// don't stomp on something the user copied from elsewhere in the meantime.
pub fn clear_if_unchanged(expected: &str) -> anyhow::Result<()> {
    let mut ctx = arboard::Clipboard::new()?;
    if ctx.get_text().unwrap_or_default() == expected {
        ctx.set_text("")?;
    }
    Ok(())
}
