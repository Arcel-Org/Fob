/// Write `data` to `path` crash-safely: write to a temp file in the same
/// directory, fsync it, then rename over the original. A same-directory
/// rename is atomic (the destination always has either the old or the new
/// content, never a partial mix) even if the process is killed, power is
/// lost, or the USB drive is yanked mid-write — unlike a direct
/// truncate-and-write, which can leave the file permanently corrupted.
pub fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp_path = dir.join(format!(".{file_name}.tmp"));

    let mut f = std::fs::File::create(&tmp_path)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}
