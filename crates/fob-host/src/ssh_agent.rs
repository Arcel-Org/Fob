/// Spawns and manages the `fob-agent` SSH agent as a child process for the
/// duration of an unlocked vault session.
///
/// Key material is handed to the child over its stdin (JSON-encoded), never
/// via argv or an environment variable — both are visible to other
/// processes on the same host (`ps`, `/proc/<pid>/environ`). The agent
/// process only ever sees keys already decrypted by fob-cli; it has no idea
/// how to unlock a vault itself.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use fob_core::types::SshKeyEntry;

pub struct SshAgentHandle {
    child: Child,
    socket_path: PathBuf,
    /// Whether `session_socket_path()` created the socket's parent directory
    /// itself (the `temp_dir()` fallback branch) as opposed to placing the
    /// socket directly in `$XDG_RUNTIME_DIR` (a directory Fob doesn't own).
    /// `Drop` only ever removes the parent directory when this is true —
    /// otherwise a session with an empty `$XDG_RUNTIME_DIR` (no D-Bus/
    /// Wayland/Pulse sockets yet, e.g. a fresh headless login) could delete
    /// the user's real per-login runtime directory outright.
    owns_socket_dir: bool,
}

impl SshAgentHandle {
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Spawn `fob-agent` (found next to the running `fob` binary) with the
    /// given keys loaded. `owns_socket_dir` should come from whatever
    /// produced `socket_path` (see `session_socket_path`) — it controls
    /// whether `Drop` is allowed to remove the socket's parent directory.
    pub fn spawn(
        socket_path: PathBuf,
        owns_socket_dir: bool,
        keys: &[SshKeyEntry],
    ) -> anyhow::Result<Self> {
        let agent_path = sibling_binary_path()?;
        let json = serde_json::to_vec(keys)?;

        let mut child = Command::new(&agent_path)
            .arg("--socket")
            .arg(&socket_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        if let Err(e) = child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(&json)
        {
            // spawn() succeeded but handing off the keys failed (e.g. the
            // child crashed/exited immediately, breaking the pipe) — kill
            // and reap it here rather than letting `child` fall out of
            // scope, which would leak an unreaped zombie or orphan (plain
            // `std::process::Child` has no such cleanup in its own Drop).
            let _ = child.kill();
            let _ = child.wait();
            return Err(e.into());
        }
        // Dropping the stdin handle above closes it, which is what
        // fob-agent's single blocking `read_to_string` is waiting on.

        Ok(Self {
            child,
            socket_path,
            owns_socket_dir,
        })
    }
}

impl Drop for SshAgentHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        // Bound how long we wait for the child to actually exit. SIGKILL
        // cannot preempt an uninterruptible (D-state) process — e.g.
        // fob-agent blocked on I/O to a yanked USB drive it was launched
        // from — so an unconditional, blocking `wait()` here could hang
        // this whole (single-threaded, synchronous) TUI forever, since this
        // Drop fires on every unlock and every SSH key add/delete. Poll
        // non-blockingly instead, and give up after a few seconds rather
        // than risk an unrecoverable freeze; a still-wedged process is left
        // as a zombie/orphan, which is recoverable (restart fob), unlike a
        // frozen UI with no way to quit.
        let mut waited = std::time::Duration::ZERO;
        let poll_interval = std::time::Duration::from_millis(50);
        let give_up_after = std::time::Duration::from_secs(3);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if waited < give_up_after => {
                    std::thread::sleep(poll_interval);
                    waited += poll_interval;
                }
                Ok(None) | Err(_) => break,
            }
        }
        // Belt-and-suspenders: SIGKILL (unlike the graceful shutdown fob-agent
        // installs a handler for) skips its own socket cleanup entirely.
        let _ = std::fs::remove_file(&self.socket_path);
        if self.owns_socket_dir {
            if let Some(parent) = self.socket_path.parent() {
                let _ = std::fs::remove_dir(parent);
            }
        }
    }
}

fn sibling_binary_path() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("could not determine directory of the running binary"))?;
    let name = if cfg!(windows) {
        "fob-agent.exe"
    } else {
        "fob-agent"
    };
    let path = dir.join(name);
    if !path.exists() {
        anyhow::bail!("fob-agent binary not found at {}", path.display());
    }
    Ok(path)
}

/// A per-session Unix socket path under the OS runtime/temp directory,
/// unique to this `fob` process.
///
/// Returns `(path, owns_parent_dir)` — `owns_parent_dir` is `true` only when
/// this function itself created the socket's parent directory (the
/// `temp_dir()` fallback below), so callers know it's safe to remove that
/// directory later. It's `false` for `$XDG_RUNTIME_DIR`, which Fob never
/// created and must never delete.
pub fn session_socket_path() -> (PathBuf, bool) {
    if let Some(runtime_dir) =
        directories::BaseDirs::new().and_then(|d| d.runtime_dir().map(PathBuf::from))
    {
        // $XDG_RUNTIME_DIR (Linux, systemd) is already a private, mode-0700
        // per-user directory — safe to place the socket directly in it.
        return (
            runtime_dir.join(format!("fob-agent-{}.sock", std::process::id())),
            false,
        );
    }

    // No XDG_RUNTIME_DIR (macOS has no equivalent; some non-systemd Linux
    // setups too). std::env::temp_dir() is per-user-private on macOS but can
    // be a shared, world-writable directory like /tmp on Linux — so rather
    // than bind the socket directly there (briefly visible to other local
    // users between bind() and the chmod 0600 in fob-agent::run(), before
    // its permissions narrow), create a private mode-0700 subdirectory first
    // and put the socket inside that instead.
    let dir = std::env::temp_dir().join(format!("fob-agent-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    (dir.join("agent.sock"), true)
}
