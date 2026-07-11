// Copyright (c) 2025 渟雲. All rights reserved.
//
// Licensed under the TOSSRCU 2025.9 License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  https://raw.githubusercontent.com/M3351AN/M3351AN/9e7630a8511b8306c62952ca1a4f1ce0cc5b784a/LICENSE
//
// -----------------------------------------------------------------------------
// File: lib.rs
// Author: 渟雲(quq[at]outlook.it)
// Date: 2026-07-11
//
// -----------------------------------------------------------------------------
// WASM entry point. Exposes `patch_file` to JS: takes the file bytes, a
// progress callback, and returns a PatchResult. The browser is yielded to
// between phases so progress paint updates reach the DOM.
// ----------------------------------------------------------------------------

mod analyzer;
mod metadata;
mod pe;

use analyzer::{analyze, apply_patch, AnalyzeOutcome};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen]
pub struct PatchResult {
    success: bool,
    error_code: String,
    already_patched: bool,
    output_filename: String,
    patched_data: Option<js_sys::Uint8Array>,
}

#[wasm_bindgen]
impl PatchResult {
    #[wasm_bindgen(getter)]
    pub fn success(&self) -> bool {
        self.success
    }
    #[wasm_bindgen(getter)]
    pub fn error_code(&self) -> String {
        self.error_code.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn already_patched(&self) -> bool {
        self.already_patched
    }
    #[wasm_bindgen(getter)]
    pub fn output_filename(&self) -> String {
        self.output_filename.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn patched_data(&self) -> JsValue {
        match &self.patched_data {
            Some(d) => d.into(),
            None => JsValue::UNDEFINED,
        }
    }
}

#[wasm_bindgen]
pub async fn patch_file(
    data: &[u8],
    filename: &str,
    on_progress: js_sys::Function,
) -> PatchResult {
    report(&on_progress, 10, "reading");
    yield_to_browser().await;

    report(&on_progress, 30, "analyzing");
    yield_to_browser().await;

    let analysis = analyze(data.to_vec());

    match analysis.outcome {
        AnalyzeOutcome::NoMzHeader => err("no_mz"),
        AnalyzeOutcome::NoValidateMethod => err("no_validate"),
        AnalyzeOutcome::AlreadyPatched => err("already_patched"),
        AnalyzeOutcome::NotFound => err("not_found"),
        AnalyzeOutcome::Patchable { offset } => {
            report(&on_progress, 70, "patching");
            yield_to_browser().await;

            let patched = apply_patch(analysis.data, offset);

            report(&on_progress, 90, "preparing");
            yield_to_browser().await;

            let bytes = js_sys::Uint8Array::from(&patched[..]);
            report(&on_progress, 100, "done");

            PatchResult {
                success: true,
                error_code: String::new(),
                already_patched: false,
                output_filename: patched_filename(filename),
                patched_data: Some(bytes),
            }
        }
    }
}

fn err(code: &str) -> PatchResult {
    PatchResult {
        success: false,
        error_code: code.to_string(),
        already_patched: code == "already_patched",
        output_filename: String::new(),
        patched_data: None,
    }
}

fn report(cb: &js_sys::Function, percent: u32, phase: &str) {
    let _ = cb.call2(&JsValue::NULL, &JsValue::from(percent), &JsValue::from(phase));
}

async fn yield_to_browser() {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        if let Some(win) = web_sys::window() {
            let _ = win.set_timeout_with_callback(&resolve);
        }
    });
    let _ = JsFuture::from(promise).await;
}

fn patched_filename(name: &str) -> String {
    let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
    format!("{}_patched.exe", stem)
}
