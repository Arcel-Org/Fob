import { readFileSync } from 'node:fs';
import { initSync, init_panic_hook, create_vault, parse_header, unlock_vault, save_vault, totp_code, passphrase_acceptable, passphrase_strength } from '/root/Git/github/Fob/web/wasm-out/fob_wasm.js';
const m = new WebAssembly.Module(readFileSync('/root/Git/github/Fob/web/wasm-out/fob_wasm_bg.wasm'));
initSync({ module: m });
init_panic_hook();
const origErr = console.error;
console.error = (...a) => origErr('CONSOLE:', ...a);

console.log('weak acceptable?', passphrase_acceptable('password123'), '| strong?', passphrase_acceptable('correct-horse-battery-staple'));
try {
  const v = create_vault('correct-horse-battery-staple', null, null, false);
  console.log('created len', v.length);
  const h = parse_header(v);
  console.log('header', JSON.stringify(h));
  const u = unlock_vault(v, 'correct-horse-battery-staple');
  const j = JSON.parse(u.json);
  console.log('unlocked slot', u.slot, 'pw count', j.passwords.length, 'fingerprint', j.fingerprint);
  j.passwords.push({id: crypto.randomUUID(), name:'n', username:'u', password:'p', url:null, notes:null, created:1, modified:1});
  const s = save_vault(v, 'correct-horse-battery-staple', 0, JSON.stringify(j));
  const u2 = unlock_vault(s, 'correct-horse-battery-staple');
  console.log('after save pw count', JSON.parse(u2.json).passwords.length);
  try { unlock_vault(v, 'wrong'); console.log('ERROR accepted'); } catch(e){ console.log('wrong rejected OK'); }
  console.log('totp len', totp_code('JBSWY3DPEHPK3PXP', 30, 6).length);
  console.log('ALL OK');
} catch (e) {
  console.log('CAUGHT:', e && e.stack ? e.stack.split('\n').slice(0,4).join(' | ') : e);
}
