#!/usr/bin/env python3
"""Headless-chromium interaction checks for web/index.html (the browser vault).

Drives a real Chromium instance over the Chrome DevTools Protocol (CDP) and
clicks/types through the actual UI exactly like a user would — this is not a
unit test of the JS functions in isolation, it renders the real page and
dispatches real DOM events (`click`, `input`) through the same delegated
listeners `index.html` wires up for a mouse/keyboard user.

Covers interaction flows that had no automated coverage before this pass:
  - search filtering (passwords view)
  - TOTP countdown display (code + seconds-remaining actually tick down)
  - auto-lock after inactivity (real timeout, sped up via an injected
    `setTimeout` shim so the test doesn't have to sleep for 15 real minutes)
  - entry list rendering/scrolling with many entries

Requires: chromium at /usr/bin/chromium, Python's `websockets` package.

Usage:
    python3 web/tests/browser_interaction_test.py

Exits 0 if every check passes, 1 otherwise (with a summary of failures).
"""
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import websockets

CHROME = "/usr/bin/chromium"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INDEX_HTML = f"file://{REPO_ROOT}/web/index.html"

PASSPHRASE = "correct-horse-battery-staple"


class CDP:
    """Minimal Chrome DevTools Protocol client — just enough to drive one page."""

    def __init__(self, ws):
        self.ws = ws
        self._id = 0
        self._pending = {}
        self._events = []
        self._listen_task = asyncio.create_task(self._listen())

    @classmethod
    async def connect(cls, ws_url):
        ws = await websockets.connect(ws_url, max_size=None)
        return cls(ws)

    async def _listen(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self._pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        fut.set_result(msg)
                else:
                    self._events.append(msg)
        except websockets.exceptions.ConnectionClosed:
            pass

    async def send(self, method, params=None):
        self._id += 1
        mid = self._id
        fut = asyncio.get_event_loop().create_future()
        self._pending[mid] = fut
        await self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        return await asyncio.wait_for(fut, timeout=20)

    async def eval(self, expr, await_promise=True):
        r = await self.send(
            "Runtime.evaluate",
            {"expression": expr, "returnByValue": True, "awaitPromise": await_promise},
        )
        res = r.get("result", {})
        if "exceptionDetails" in res:
            raise RuntimeError(json.dumps(res["exceptionDetails"], indent=2))
        return res.get("result", {}).get("value")

    async def wait_for_event(self, method, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            for i, e in enumerate(self._events):
                if e.get("method") == method:
                    return self._events.pop(i)
            await asyncio.sleep(0.05)
        raise TimeoutError(f"timed out waiting for {method}")

    async def close(self):
        self._listen_task.cancel()
        await self.ws.close()


class Chromium:
    """Launches/kills one headless chromium process and opens CDP pages on it."""

    def __init__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="fob-web-test-")
        self.proc = None
        self.port = None

    def start(self):
        self.proc = subprocess.Popen(
            [
                CHROME,
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                f"--user-data-dir={self.tmpdir}/profile",
                "--remote-debugging-port=0",
            ],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            line = self.proc.stderr.readline()
            if not line:
                continue
            if "DevTools listening on" in line:
                ws_url = line.strip().split("DevTools listening on ")[1]
                self.port = ws_url.split(":")[2].split("/")[0]
                return
        raise RuntimeError("chromium never printed a DevTools listening port")

    async def open_page(self, on_new_document_js=None):
        """Open a blank tab, optionally install a bootstrap script that runs
        before any page script, then navigate it to index.html and wait for load."""
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/json/new?about:blank", method="PUT")
        with urllib.request.urlopen(req) as r:
            info = json.loads(r.read())
        cdp = await CDP.connect(info["webSocketDebuggerUrl"])
        await cdp.send("Page.enable")
        await cdp.send("Runtime.enable")
        if on_new_document_js:
            await cdp.send("Page.addScriptToEvaluateOnNewDocument", {"source": on_new_document_js})
        await cdp.send("Page.navigate", {"url": INDEX_HTML})
        await cdp.wait_for_event("Page.loadEventFired")
        # Let the DOMContentLoaded listener in index.html finish wiring up.
        await asyncio.sleep(0.3)
        return cdp

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ── Shared page-side helpers, injected as JS strings ────────────────────────

JS_SET_VALUE = """
(function(){{
  const el = document.getElementById({id!r});
  el.value = {value!r};
  el.dispatchEvent(new Event('input', {{bubbles:true}}));
}})()
"""

JS_CLICK = """
(function(){{
  const el = document.querySelector({sel!r});
  if (!el) throw new Error('selector not found: ' + {sel!r});
  el.click();
}})()
"""


async def set_value(cdp, elem_id, value):
    await cdp.eval(JS_SET_VALUE.format(id=elem_id, value=value), await_promise=False)


async def click(cdp, selector):
    await cdp.eval(JS_CLICK.format(sel=selector), await_promise=False)


async def create_vault(cdp, passphrase=PASSPHRASE):
    """Drives the real "Create vault" card exactly like a first-time user."""
    await set_value(cdp, "create-pass", passphrase)
    await set_value(cdp, "create-pass2", passphrase)
    await click(cdp, '[data-action="create-vault"]')
    await asyncio.sleep(0.6)
    err = await cdp.eval("document.getElementById('create-err').textContent")
    if err:
        raise RuntimeError(f"vault creation failed: {err}")
    display = await cdp.eval("getComputedStyle(document.getElementById('vault-ui')).display")
    if display == "none":
        raise RuntimeError("vault-ui did not become visible after create-vault")


async def add_password(cdp, name, username, password, url=""):
    await click(cdp, '[data-action="add"]')
    await asyncio.sleep(0.1)
    await set_value(cdp, "mf-name", name)
    await set_value(cdp, "mf-username", username)
    await set_value(cdp, "mf-password", password)
    if url:
        await set_value(cdp, "mf-url", url)
    await click(cdp, '[data-action="save-entry"]')
    await asyncio.sleep(0.3)


async def add_totp(cdp, issuer, account, secret):
    await click(cdp, '.nav-item[data-view="totp"]')
    await asyncio.sleep(0.1)
    await click(cdp, '[data-action="add"]')
    await asyncio.sleep(0.1)
    await set_value(cdp, "mf-issuer", issuer)
    await set_value(cdp, "mf-account", account)
    await set_value(cdp, "mf-secret", secret)
    await click(cdp, '[data-action="save-entry"]')
    await asyncio.sleep(0.3)


async def lock_vault(cdp):
    """Click the sidebar lock action and wait for the lock screen to show."""
    await click(cdp, '[data-action="lock"]')
    await asyncio.sleep(0.3)


async def unlock_vault(cdp, passphrase=PASSPHRASE):
    """Drive the unlock card: type the passphrase, submit, wait for vault UI."""
    await set_value(cdp, "passphrase", passphrase)
    await click(cdp, '[data-action="unlock"]')
    await asyncio.sleep(0.6)
    err = await cdp.eval("document.getElementById('unlock-err').textContent")
    if err:
        raise RuntimeError(f"unlock failed: {err}")
    display = await cdp.eval("getComputedStyle(document.getElementById('vault-ui')).display")
    if display == "none":
        raise RuntimeError("vault-ui did not become visible after unlock")


# ── Individual checks — each returns (ok: bool, detail: str) ────────────────


async def check_search_filtering(chrome):
    cdp = await chrome.open_page()
    try:
        await create_vault(cdp)
        await add_password(cdp, "GitHub Work", "alice", "gh-pw-1")
        await add_password(cdp, "GitLab Personal", "bob", "gl-pw-1")
        await add_password(cdp, "Amazon Shopping", "alice2", "am-pw-1")

        all_count = await cdp.eval("document.getElementById('entry-list').children.length")
        if all_count != 3:
            return False, f"expected 3 entries before searching, saw {all_count}"

        await set_value(cdp, "search", "git")
        await asyncio.sleep(0.2)
        names = await cdp.eval(
            "[...document.querySelectorAll('#entry-list .entry-name')].map(e=>e.textContent)"
        )
        view_count = await cdp.eval("document.getElementById('view-count').textContent")
        if sorted(names) != sorted(["GitHub Work", "GitLab Personal"]):
            return False, f"searching 'git' should show GitHub/GitLab only, got {names}"
        if "2" not in view_count:
            return False, f"view-count should reflect the filtered 2 items, got {view_count!r}"

        # Clearing the search restores all entries.
        await set_value(cdp, "search", "")
        await asyncio.sleep(0.2)
        restored = await cdp.eval("document.getElementById('entry-list').children.length")
        if restored != 3:
            return False, f"clearing search should restore all 3 entries, saw {restored}"

        # A query matching nothing shows the empty state, not a stale list.
        await set_value(cdp, "search", "doesnotexist")
        await asyncio.sleep(0.2)
        empty_shown = await cdp.eval("!!document.querySelector('#entry-list .entry-empty')")
        if not empty_shown:
            return False, "a non-matching search should render the empty-state message"

        return True, "filters to matching entries, restores on clear, empty state on no match"
    finally:
        await cdp.close()


async def check_totp_countdown(chrome):
    cdp = await chrome.open_page()
    try:
        await create_vault(cdp)
        await add_totp(cdp, "Example Co", "alice@example.com", "JBSWY3DPEHPK3PXP")

        totp_id = await cdp.eval("vaultJSON.totp[0].id")
        code1 = await cdp.eval(f"document.getElementById('tc-{totp_id}').textContent")
        secs1_text = await cdp.eval(f"document.getElementById('ts-{totp_id}').textContent")
        m1 = re.match(r"^(\d+)s$", secs1_text)
        if not re.match(r"^\d{3} \d{3}$", code1):
            return False, f"TOTP code should render as 'XXX XXX', got {code1!r}"
        if not m1:
            return False, f"seconds-remaining should render as '<n>s', got {secs1_text!r}"

        await asyncio.sleep(1.2)
        secs2_text = await cdp.eval(f"document.getElementById('ts-{totp_id}').textContent")
        m2 = re.match(r"^(\d+)s$", secs2_text)
        if not m2:
            return False, f"seconds-remaining should still render as '<n>s' after a tick, got {secs2_text!r}"
        s1, s2 = int(m1.group(1)), int(m2.group(1))
        # It must have ticked down by ~1s, or wrapped to a fresh ~30s period.
        ticked_down = 0 <= (s1 - s2) <= 2
        wrapped = s2 > s1
        if not (ticked_down or wrapped):
            return False, f"countdown did not advance: {s1}s -> {s2}s after 1.2s"

        return True, f"code renders as digits, countdown ticked {s1}s -> {s2}s"
    finally:
        await cdp.close()


async def check_many_entries_rendering(chrome):
    cdp = await chrome.open_page()
    try:
        await create_vault(cdp)
        n = 60
        await cdp.eval(
            f"""
            (function(){{
              vaultJSON.passwords = [];
              for (let i = 0; i < {n}; i++) {{
                vaultJSON.passwords.push({{
                  id: 'test-'+i, created: nowSecs(), modified: nowSecs(),
                  name: 'Entry '+String(i).padStart(3,'0'), username: 'user'+i, password: 'pw'+i,
                }});
              }}
              renderList();
            }})()
            """,
            await_promise=False,
        )
        rendered = await cdp.eval("document.getElementById('entry-list').children.length")
        if rendered != n:
            return False, f"expected {n} rendered entry rows, saw {rendered}"

        # The list must actually be scrollable (not clipped with overflow
        # hidden) once it has more entries than fit on screen.
        scroll_h = await cdp.eval("document.getElementById('entry-list').scrollHeight")
        client_h = await cdp.eval("document.getElementById('entry-list').clientHeight")
        if scroll_h <= client_h:
            return False, f"entry-list should overflow with {n} entries (scrollHeight {scroll_h} <= clientHeight {client_h})"

        # Actually scroll it and confirm the browser honored it (catches a
        # stray overflow:hidden / fixed-height regression that TestBackend-style
        # text assertions can't see, since it's a real layout property).
        await cdp.eval("document.getElementById('entry-list').scrollTop = 99999", await_promise=False)
        scroll_top = await cdp.eval("document.getElementById('entry-list').scrollTop")
        if scroll_top <= 0:
            return False, "entry-list did not scroll when scrollTop was set"

        # Clicking the last (only reachable by scrolling) entry still selects
        # it correctly — the scrolled area isn't just visually there but dead.
        await click(cdp, f'[data-select-idx="{n-1}"]')
        await asyncio.sleep(0.2)
        selected_name = await cdp.eval("document.querySelector('.entry-item.selected .entry-name')?.textContent")
        expected = f"Entry {n-1:03d}"
        if selected_name != expected:
            return False, f"selecting the last scrolled-to entry should show {expected!r}, got {selected_name!r}"

        return True, f"{n} entries render, list overflows/scrolls, last entry is selectable"
    finally:
        await cdp.close()


async def check_autolock_timeout(chrome):
    # Speed up the vault's real 15-minute LOCK_MS (900_000ms) by intercepting
    # setTimeout before any page script runs — this changes only the test's
    # clock, not index.html, so the real doLock()/resetLockTimer() logic is
    # what's actually exercised. Only the ~15-minute-scale delay is touched;
    # shorter delays (toasts, clipboard-clear) are left alone so they don't
    # race the interactions the test still needs to perform (create vault,
    # open a modal, save an entry) before the sped-up lock fires.
    shim = """
    (function(){
      const orig = window.setTimeout;
      window.setTimeout = function(fn, delay, ...args){
        return orig(fn, delay > 500000 ? 1500 : delay, ...args);
      };
    })();
    """
    cdp = await chrome.open_page(on_new_document_js=shim)
    try:
        await create_vault(cdp)
        await add_password(cdp, "Test Entry", "user", "pw")

        # No further synthetic input events after this point (every click
        # above reset the lock timer) — the point is to observe the sped-up
        # *inactivity* timeout actually firing on its own.
        await asyncio.sleep(2.2)

        lock_display = await cdp.eval("getComputedStyle(document.getElementById('lock-screen')).display")
        vault_display = await cdp.eval("getComputedStyle(document.getElementById('vault-ui')).display")
        toast_text = await cdp.eval("document.getElementById('toast').textContent")
        vault_json_cleared = await cdp.eval("vaultJSON === null")

        if lock_display == "none":
            return False, "lock-screen should be visible again after the auto-lock timeout"
        if vault_display != "none":
            return False, "vault-ui should be hidden again after the auto-lock timeout"
        if not vault_json_cleared:
            return False, "vaultJSON should be cleared (null) once auto-locked"
        if "locked after inactivity" not in toast_text:
            return False, f"expected an inactivity-lock toast, got {toast_text!r}"

        return True, "vault auto-locked and re-showed the lock screen after the (sped-up) inactivity timeout"
    finally:
        await cdp.close()


async def check_v4_roundtrip(chrome):
    """Prove a v4 (Argon2id) vault fully round-trips IN THE BROWSER: create it
    through the real UI, confirm the header says format v4 / Argon2id, add a
    password + a TOTP, lock, re-unlock, and confirm both entries persisted.
    This is the core Phase B/E guarantee — the browser runs fob-core's Rust
    crypto (embedded WASM), so what it writes is byte-compatible with the CLI."""
    cdp = await chrome.open_page()
    try:
        await create_vault(cdp)

        # The header must report format v4 + Argon2id — i.e. the WASM (Rust)
        # create path, not the old WebCrypto v3/PBKDF2 path.
        hdr = await cdp.eval(
            "(function(){ var h = FobWasm.parse_header(vaultFileData); return JSON.stringify(h); })()"
        )
        hdr = json.loads(hdr)
        if hdr["formatVersion"] != 4:
            return False, f"expected formatVersion 4 (Argon2id), got {hdr['formatVersion']}"
        if hdr["kdfAlgorithm"] != "Argon2id":
            return False, f"expected Argon2id KDF, got {hdr['kdfAlgorithm']}"
        if not hdr["fingerprint"]:
            return False, "header fingerprint should be non-empty"

        await add_password(cdp, "Vault Roundtrip", "alice", "roundtrip-pw")
        await add_totp(cdp, "RT Co", "bob@example.com", "JBSWY3DPEHPK3PXP")

        # Lock then re-unlock with the same passphrase — entry data must
        # survive the full encrypt→persist→decrypt cycle through WASM.
        await lock_vault(cdp)
        await unlock_vault(cdp)

        pws = await cdp.eval("vaultJSON.passwords.length")
        totps = await cdp.eval("vaultJSON.totp.length")
        if pws != 1 or totps != 1:
            return False, f"after re-unlock expected 1 password & 1 TOTP, got {pws} & {totps}"

        # TOTP secret must have come back as the raw byte array (Rust shape),
        # and algorithm as "Sha1", so a subsequent save stays interop-clean.
        secret = await cdp.eval("vaultJSON.totp[0].secret")
        algo = await cdp.eval("vaultJSON.totp[0].algorithm")
        if not isinstance(secret, list) or not all(isinstance(b, int) and 0 <= b <= 255 for b in secret):
            return False, f"TOTP secret should be a raw byte array after unlock, got {secret!r}"
        if algo != "Sha1":
            return False, f"TOTP algorithm should be 'Sha1', got {algo!r}"

        # Editing that TOTP and saving must produce a still-valid vault that
        # re-unlocks — catches the base32↔bytes boundary being lossy.
        await click(cdp, '.nav-item[data-view="totp"]')
        await asyncio.sleep(0.1)
        await click(cdp, '[data-edit-type="totp"]')
        await asyncio.sleep(0.1)
        await click(cdp, '[data-action="save-entry"]')
        await asyncio.sleep(0.3)
        await lock_vault(cdp)
        await unlock_vault(cdp)
        totps_after = await cdp.eval("vaultJSON.totp.length")
        if totps_after != 1:
            return False, f"after edit+relock, expected 1 TOTP, got {totps_after}"

        return True, "v4 Argon2id vault created, entries saved, locked/re-unlocked in-browser, TOTP bytes round-trip"
    finally:
        await cdp.close()


async def check_passphrase_policy_enforced(chrome):
    """The create-vault card must refuse weak passphrases using the same
    shared Rust policy the CLI uses (length >= 14, entropy floor, blocklist,
    diversity) — surfaced through FobWasm.passphrase_rejection_reason."""
    cdp = await chrome.open_page()
    try:
        # A blocklisted / too-short passphrase must be refused before any
        # vault bytes are produced.
        await set_value(cdp, "create-pass", "password123")
        await set_value(cdp, "create-pass2", "password123")
        await click(cdp, '[data-action="create-vault"]')
        await asyncio.sleep(0.4)
        err = await cdp.eval("document.getElementById('create-err').textContent")
        if not err:
            return False, "weak passphrase should have been rejected, but create succeeded"

        # A strong passphrase still creates a vault.
        await create_vault(cdp)
        return True, f"weak passphrase rejected ('{err}'), strong passphrase accepted"
    finally:
        await cdp.close()


CHECKS = [
    ("search filtering", check_search_filtering),
    ("TOTP countdown display", check_totp_countdown),
    ("entry list rendering/scrolling with many entries", check_many_entries_rendering),
    ("auto-lock after inactivity timeout", check_autolock_timeout),
    ("v4 Argon2id vault round-trips in-browser", check_v4_roundtrip),
    ("passphrase policy enforced on create", check_passphrase_policy_enforced),
]


async def main():
    if not os.path.exists(CHROME):
        print(f"SKIP: {CHROME} not found")
        return 1
    chrome = Chromium()
    chrome.start()
    results = []
    try:
        for name, fn in CHECKS:
            try:
                ok, detail = await fn(chrome)
            except Exception as e:  # noqa: BLE001 — report, don't crash the whole run
                ok, detail = False, f"EXCEPTION: {e}"
            results.append((name, ok, detail))
            print(f"{'PASS' if ok else 'FAIL'}  {name}\n      {detail}")
    finally:
        chrome.stop()

    failed = [r for r in results if not r[1]]
    print()
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
