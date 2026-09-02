# Fob — Usability Testing Script

> **This is a script for a real, first-time human to sit down and follow.**
> No real person has used this product yet. Everything below is a set of
> tasks for someone who has never seen Fob before, has not read the source,
> and does not know the "correct" sequence of keystrokes or clicks.
>
> This document — and any amount of automated test coverage (rendering
> tests, headless-browser interaction checks, unit tests) — **is not a
> substitute for watching a real person actually try this.** Automated tests
> only confirm that the code does what the person who wrote the test
> expected it to do; they cannot tell you that a label is confusing, that a
> keybinding is unguessable, that an error message is meaningless to someone
> who didn't write the parser that produced it, or that a first-time user
> got stuck and gave up. Run this with an actual person, watch over their
> shoulder (or screen-share), and write down what actually happened — not
> what was supposed to happen.
>
> Do not coach. If the tester is stuck, let them be stuck for at least a
> minute before offering a hint, and **write down that they got stuck** —
> that's the most valuable data point in this whole document.

---

## How to run this

1. Pick a tester who has not used Fob and ideally has not read this repo.
   Two testers (one non-technical, one technical) is better than one if
   you can get them — password-manager and SSH-key concepts land very
   differently depending on background.
2. Give them **no instructions beyond "set up and use this password
   manager"** — don't explain the vault creation, don't explain
   slots/decoy/duress terminology, don't tell them where the "generate
   password" button is.
   The point is to find out if they can find it themselves.
3. Sit where you can see their screen and their face, but resist narrating
   or helping. Time each task loosely (a stopwatch on your phone is fine —
   precision doesn't matter, "gave up after 3 minutes" does).
4. Fill in the blanks under each task as you go. There's a free-form
   "Confusion / friction notes" line after every task — use it even
   (especially) when the task technically succeeded but wasn't obvious.
5. Run the **browser vault** as the primary interface — it is where all
   day-to-day browsing/editing happens. Also run the **CLI** for the setup
   path (`fob format` on a USB drive), ideally with different testers (or
   the same tester on different days) so the second run isn't biased by
   having already learned the vault's concepts on the first.

**Session info**

- Date: ______________________  Tester: ______________________
- Tester's self-rated familiarity with password managers (1–5): _____
- Tester's self-rated familiarity with SSH / terminal use (1–5): _____
- Interface tested this session:  ☐ Browser vault (`index.html`)   ☐ CLI (`fob format` / `fob status`)
- Build/version tested: ______________________

---

## Setup for the person running the session (not the tester)

- **CLI**: build `fob` (`cargo build --release -p fob-cli`), have a real
  spare USB drive plugged in (or one it's OK to erase — `fob format` will
  wipe it).
- **Browser vault**: have `web/index.html` reachable — opening it directly
  as a `file://` URL is the real-world case most users will hit, so test
  that path, not a localhost dev server, unless you're specifically also
  checking the hosted-on-a-webserver case.
- Have a way to capture screenshots or screen-recording if the tester hits
  something confusing — a picture of the exact screen is worth more than a
  paraphrase written down five minutes later.

---

## Task list

Run these in order — later tasks (edit, lock/unlock) depend on entries
created in earlier ones. The task wording is deliberately vague about *how*
("add a password" not "press `a` then Tab three times") — that vagueness is
the point.

### 1. Set up a vault for the first time

**Ask the tester to:** get this password manager set up and ready to use,
starting from nothing (no existing vault).

- Did they find the entry point without help? Y / N
- Did they understand what a "passphrase" was being asked for here, as
  distinct from a website password? Y / N
- CLI only: did they correctly identify which USB drive to pick if more
  than one was plugged in, and did the format/erase warning read clearly?
- Did they read (or skip past) any warning about data being erased?
- Time to a usable, unlocked vault: ______
- Confusion / friction notes:
  ___________________________________________________________________
  ___________________________________________________________________

### 2. Add a password entry

**Ask the tester to:** save a password for some made-up site (e.g. "a
GitHub login") in the vault.

- Did they find the "add" action without help?
- Did they understand which field was username vs. password vs. site name?
- Confusion / friction notes:
  ___________________________________________________________________

### 3. Use the generate-password feature

**Ask the tester to:** create a *second* password entry, but this time have
the app come up with the password for them instead of typing one.

- Did they discover the generate feature unprompted, or did they type a
  password by hand and need a nudge that generation exists?
- If they found it: was it obvious what had happened (i.e. that a strong
  password was inserted into the field), or did the field just seem to
  change with no explanation?
- Confusion / friction notes:
  ___________________________________________________________________

### 4. Add a TOTP (two-factor) entry

**Ask the tester to:** add a two-factor / authenticator code entry. Give
them a throwaway base32 secret if they don't have one handy, e.g.
`JBSWY3DPEHPK3PXP` (this is just a test string, not a real account).

- Did they understand this was a *different kind* of entry from a password,
  before being told?
- Once added, did they find where the live code and countdown are shown?
- Did they understand what the countdown meant (code about to change) or
  did it seem like a decoration?
- Confusion / friction notes:
  ___________________________________________________________________

### 5. Import an SSH key

**Ask the tester to:** import an existing SSH key into the vault. Provide a
throwaway keypair generated just for this test (`ssh-keygen -t ed25519 -f
/tmp/usability-test-key -N ""` — do **not** use anyone's real key).

- Did they understand which file/field was the public key vs. private key?
- CLI only (SSH agent path): after import, did they notice anything
  indicating the key is now available to an SSH agent (or did they not
  look/care)?
- Did anything in the flow suggest their key had a passphrase and needed it
  stripped first, if they tried a passphrase-protected key?
- Confusion / friction notes:
  ___________________________________________________________________

### 6. Edit an existing entry

**Ask the tester to:** go back and change the username on the very first
password entry they created in Task 2.

- Did they find the edit action without help (vs. trying to delete and
  re-add)?
- Did the form come up pre-filled with the existing values, and did that
  match their expectation?
- Confusion / friction notes:
  ___________________________________________________________________

### 7. Lock and unlock

**Ask the tester to:** lock the vault, then unlock it again with their
passphrase.

- Did they find the lock action without help?
- After locking, did they correctly conclude their data was no longer
  visible/accessible (ask them, don't just observe the screen)?
- Did unlocking again feel like the same "enter a passphrase" step as the
  very first setup, or did it feel different/inconsistent?
- Confusion / friction notes:
  ___________________________________________________________________

### 8. Try the decoy passphrase

Before this task, **you** (the session runner) should have set a decoy
passphrase during Task 1 if the tool offered it, or set one now via an
edit/settings path if available — the tester should not have to invent one.

**Ask the tester to:** lock the vault, then unlock it using the *decoy*
passphrase instead of their main one, and tell you what they notice.

- Did they notice they were looking at a *different* vault (different/fake
  entries) rather than their real one?
- Was it clear this was intentional behavior and not a bug, or did it look
  broken to them?
- Did they understand *why* this feature might exist, unprompted?
- Confusion / friction notes:
  ___________________________________________________________________

### 9. Try the duress passphrase

Same setup note as Task 8 — have a duress passphrase already configured
before this task starts.

> **Warning for the session runner:** the duress passphrase is designed to
> destroy the vault. Only run this task against a throwaway
> vault/USB drive you're fully prepared to lose, and confirm you have
> everything you need recorded (screenshots, notes) from Tasks 1–8 first.

**Ask the tester to:** lock the vault, then unlock it using the *duress*
passphrase, and tell you what they notice.

- What did they see happen? (Expected: it behaves like a wrong passphrase —
  no special message, no obvious "vault destroyed" confirmation, since the
  whole point is that it's silent and doesn't tip off an attacker.)
- Did the silence itself register as strange/wrong to them, or did it read
  as an ordinary failed-unlock attempt?
- Confirm afterward (by trying the *main* passphrase) that the vault is in
  fact now gone/wiped — record what you observe.
- Confusion / friction notes:
  ___________________________________________________________________

---

## Wrap-up questions (ask after all tasks)

- On a scale of 1–5, how confident are they that their data is actually
  safe? Why that number?
- What was the single most confusing moment of the whole session?
- Was there any point where they weren't sure if something had worked or
  not (silent success/failure)?
- Would they trust this with a real password, today, as-is? Why or why not?
- Anything they expected to be able to do that they couldn't find?

## If you ran both interfaces

- Which one did they complete tasks faster on?
- Which one did they say they'd rather use day-to-day, and why?
- Did any concept (decoy/duress especially) click on the second interface
  because they'd already learned it on the first, or did they still
  struggle both times?

---

## After the session

File anything that came up as a real issue — a confusing label, a missing
piece of feedback, a keybinding nobody could guess — as its own actionable
note, separate from this filled-in form. This form is raw observation data;
turning it into fixes is a follow-up step, not something to skip because
"the tester eventually got there."
