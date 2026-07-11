﻿# SPT_Fuyu_Patcher_Web

A pure-frontend web-based patcher for the SPT Fuyu launcher. All processing happens entirely in the browser via WebAssembly — no server uploads, no external dependencies.

- **Rust + WASM** (compiled with `wasm-pack`, no Blazor/.NET runtime)
- Pure frontend — files never leave the browser
- No residual files, no registry changes, no downloads

## How it works

Patches `SPT.Launcher.exe` by flipping a single IL byte (`0x16` → `0x25`) inside `SPT.Launcher.Helpers.ValidationUtil.Validate()`, bypassing the EFT live install validation. The patcher hand-parses the PE/COFF header and ECMA-335 .NET metadata in Rust to locate the target method's IL body, then searches for the known byte pattern.

## Build

```bash
# Install wasm-pack
cargo install wasm-pack

# Build the WASM package (output: wwwroot/pkg/)
wasm-pack build --target web --release --out-dir wwwroot/pkg

# Serve wwwroot with any static file server, e.g.:
npx serve wwwroot
```

## Project structure

```
src/            Rust source (PE parsing, metadata reader, analyzer, WASM bindings)
wwwroot/        Static frontend (HTML, CSS, vanilla JS ES modules)
  js/app.js     UI controller — loads WASM, wires events, drives patch flow
  js/i18n.js    Localization (zh/en)
.github/        CI workflow (Rust + wasm-pack → GitHub Pages)
```
