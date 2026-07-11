// Copyright (c) 2025 渟雲. All rights reserved.
//
// Licensed under the TOSSRCU 2025.9 License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  https://raw.githubusercontent.com/M3351AN/M3351AN/9e7630a8511b8306c62952ca1a4f1ce0cc5b784a/LICENSE
//
// -----------------------------------------------------------------------------
// File: analyzer.rs
// Author: 渟雲(quq[at]outlook.it)
// Date: 2026-07-11
//
// -----------------------------------------------------------------------------
// Orchestration: locate the Validate() method in the file, search for the
// unpatched/patched IL byte sequences around it, and apply the one-byte patch.
// ----------------------------------------------------------------------------

use crate::metadata::find_validate_method_rva;
use crate::pe::{find_mz_headers, PeImage};

const UNPATCHED: [u8; 4] = [0x16, 0xFE, 0x01, 0x2A];
const PATCHED: [u8; 4] = [0x25, 0xFE, 0x01, 0x2A];

const SEARCH_BACK: usize = 500;
const SEARCH_FORWARD: usize = 1500;

pub enum AnalyzeOutcome {
    Patchable { offset: usize },
    AlreadyPatched,
    NotFound,
    NoValidateMethod,
    NoMzHeader,
}

pub struct Analysis {
    pub data: Vec<u8>,
    pub outcome: AnalyzeOutcome,
}

pub fn analyze(data: Vec<u8>) -> Analysis {
    let headers = find_mz_headers(&data);
    if headers.is_empty() {
        return Analysis { data, outcome: AnalyzeOutcome::NoMzHeader };
    }

    for mz in &headers {
        let pe = match PeImage::parse(&data, mz.offset) {
            Some(p) => p,
            None => continue,
        };
        if !pe.is_managed() {
            continue;
        }
        let rva = match find_validate_method_rva(&pe) {
            Some(r) => r,
            None => continue,
        };
        let method_abs = match pe.rva_to_file_offset(rva) {
            Some(o) => o,
            None => continue,
        };

        let outcome = search_near_method(pe.data(), method_abs);
        return Analysis { data, outcome };
    }

    Analysis { data, outcome: AnalyzeOutcome::NoValidateMethod }
}

fn search_near_method(data: &[u8], method_abs: usize) -> AnalyzeOutcome {
    let start = method_abs.saturating_sub(SEARCH_BACK);
    let end = (method_abs + SEARCH_FORWARD).min(data.len());

    let window = match data.get(start..end) {
        Some(w) => w,
        None => return AnalyzeOutcome::NotFound,
    };

    let mut already_patched = false;
    let mut first_unpatched = None;
    for i in 0..window.len().saturating_sub(3) {
        let w = &window[i..i + 4];
        if w == PATCHED {
            already_patched = true;
        } else if w == UNPATCHED && first_unpatched.is_none() {
            first_unpatched = Some(start + i);
        }
    }

    if already_patched {
        AnalyzeOutcome::AlreadyPatched
    } else {
        match first_unpatched {
            Some(offset) => AnalyzeOutcome::Patchable { offset },
            None => AnalyzeOutcome::NotFound,
        }
    }
}

pub fn apply_patch(mut data: Vec<u8>, offset: usize) -> Vec<u8> {
    if offset < data.len() {
        data[offset] = 0x25;
    }
    data
}
