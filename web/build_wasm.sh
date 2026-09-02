#!/usr/bin/env bash
# Build the self-contained browser crypto bundle: web/fob-wasm.js
#
# Compiles crates/fob-wasm (which wraps fob-core) to wasm32-unknown-unknown,
# runs wasm-bindgen to get a classic (no-modules) script that works on
# file://, then appends a bootstrap that base64-embeds the .wasm so the whole
# crypto module ships as ONE JS file with no external fetch.
#
# Requirements: wasm32-unknown-unknown target + wasm-bindgen-cli installed.
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version "$(grep wasm-bindgen Cargo.lock -A1 | grep version | head -1 | awk '{print $3}' | tr -d '"')"
#
# Output: web/fob-wasm.js  (committed; the browser vault loads this)

set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

# Locate a usable C compiler (the system `cc` is shadowed by a tool shim here).
CC_BIN="${CC:-/usr/bin/gcc}"
export CARGO_HOME="${CARGO_HOME:-$ROOT/.cargo-home}"
export CC="$CC_BIN"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$CC_BIN"

WASM_BINDGEN="${WASM_BINDGEN:-$CARGO_HOME/bin/wasm-bindgen}"

echo ">> building fob-wasm for wasm32-unknown-unknown (release)"
cargo build -p fob-wasm --target wasm32-unknown-unknown --release

OUT="$ROOT/web/wasm-tmp"
rm -rf "$OUT"; mkdir -p "$OUT"
echo ">> generating classic-script glue with wasm-bindgen"
"$WASM_BINDGEN" \
  "$ROOT/target/wasm32-unknown-unknown/release/fob_wasm.wasm" \
  --out-dir "$OUT" --target no-modules

echo ">> inlining wasm as base64 + bootstrap into web/fob-wasm.js"
python3 - "$OUT/fob_wasm.js" "$OUT/fob_wasm_bg.wasm" "$ROOT/web/fob-wasm.js" "$ROOT/web/index.template.html" "$ROOT/web/index.html" "$ROOT/site/header-inspector.template.html" "$ROOT/site/header-inspector.html" <<'PY'
import base64, sys
glue, wasm, bundle_out, template_out, index_out, inspector_tmpl, inspector_out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7]
with open(glue) as f:
    glue_js = f.read()
with open(wasm, 'rb') as f:
    b64 = base64.b64encode(f.read()).decode('ascii')

bootstrap = f'''
// ── auto-generated: base64-embedded wasm + bootstrap ──────────────────────
// Built from crates/fob-wasm via build_wasm.sh. Do not edit by hand.
(function () {{
  "use strict";
  const B64 = "{b64}";
  function b64ToBytes(s) {{
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }}
  const module = new WebAssembly.Module(b64ToBytes(B64));
  wasm_bindgen.initSync({{ module }});
  window.FobWasm = wasm_bindgen;
  if (window.__FobWasmReady) window.__FobWasmReady(wasm_bindgen);
}})();
'''

with open(bundle_out, 'w') as f:
    f.write(glue_js)
    f.write("\n")
    f.write(bootstrap)

# Inline the bundle into the self-contained pages at the marker so they need
# no external fetch. Both pages are generated from their .template.html
# sources (the hand-edited files with the marker); the built .html files are
# the self-contained deliverables shipped to the USB / GitHub Pages.
marker = "<!--FOBWASM_INLINE_MARKER-->"
inline = "<script>\n" + glue_js + "\n" + bootstrap + "\n</script>"

# 1) index.html ← index.template.html
with open(template_out) as f:
    html = f.read()
if marker not in html:
    raise SystemExit(f"marker {marker!r} not found in {template_out}")
html = html.replace(marker, inline)
with open(index_out, 'w') as f:
    f.write(html)

# 2) header-inspector.html ← header-inspector.template.html
with open(inspector_tmpl) as f:
    html = f.read()
if marker not in html:
    raise SystemExit(f"marker {marker!r} not found in {inspector_tmpl}")
html = html.replace(marker, inline)
with open(inspector_out, 'w') as f:
    f.write(html)
print(f"wrote {bundle_out}")
print(f"inlined into {index_out}")
print(f"inlined into {inspector_out}")
PY

echo ">> done. bundle: $(wc -c < web/fob-wasm.js) bytes, index.html: $(wc -c < web/index.html) bytes"
