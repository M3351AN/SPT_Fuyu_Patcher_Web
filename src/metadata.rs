// Copyright (c) 2025 渟雲. All rights reserved.
//
// Licensed under the TOSSRCU 2025.9 License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  https://raw.githubusercontent.com/M3351AN/M3351AN/9e7630a8511b8306c62952ca1a4f1ce0cc5b784a/LICENSE
//
// -----------------------------------------------------------------------------
// File: metadata.rs
// Author: 渟雲(quq[at]outlook.it)
// Date: 2026-07-11
//
// -----------------------------------------------------------------------------
// Minimal ECMA-335 (II.22/II.24) metadata reader. Only enough to locate the
// `SPT.Launcher.Helpers.ValidationUtil.Validate` method and return its RVA.
// ----------------------------------------------------------------------------

use crate::pe::PeImage;

const META_SIGNATURE: u32 = 0x424A_5342; // "BSJB"

const T_MODULE: u8 = 0x00;
const T_TYPEREF: u8 = 0x01;
const T_TYPEDEF: u8 = 0x02;
const T_FIELDPTR: u8 = 0x03;
const T_FIELD: u8 = 0x04;
const T_METHODPTR: u8 = 0x05;
const T_METHODDEF: u8 = 0x06;
const T_PARAM: u8 = 0x08;
const T_MODULEREF: u8 = 0x1A;
const T_TYPESPEC: u8 = 0x1B;
const T_ASSEMBLYREF: u8 = 0x23;

const TARGET_NAMESPACE: &str = "SPT.Launcher.Helpers";
const TARGET_TYPE: &str = "ValidationUtil";
const TARGET_METHOD: &str = "Validate";

pub fn find_validate_method_rva(pe: &PeImage) -> Option<u32> {
    let data = pe.data();
    let cli_off = pe.rva_to_file_offset(cli_metadata_rva(pe)?)?;
    let meta = Meta::parse(data, cli_off)?;

    let ctx = IndexCtx::build(&meta)?;
    let strings = meta.strings?;

    let body = meta.tables_body;
    let mut cursor = body;
    let mut typedef_off = None;
    let mut methoddef_off = None;

    for t in 0..=T_METHODDEF {
        if !ctx.present(t) {
            continue;
        }
        if t == T_TYPEDEF {
            typedef_off = Some(cursor);
        }
        if t == T_METHODDEF {
            methoddef_off = Some(cursor);
        }
        let row = row_size(t, &ctx)?;
        cursor = cursor.checked_add(row.checked_mul(ctx.rows[t as usize] as usize)?)?;
    }

    let typedef_off = typedef_off?;
    let methoddef_off = methoddef_off?;

    let typedef_row = row_size(T_TYPEDEF, &ctx)?;
    let typedef_rows = ctx.rows[T_TYPEDEF as usize] as usize;
    let mut found_type = None;
    for i in 0..typedef_rows {
        let row_off = typedef_off + i * typedef_row;
        let mut c = Cursor::new(data, row_off);
        c.skip(4)?;
        let name_idx = c.read_index(ctx.string)?;
        let ns_idx = c.read_index(ctx.string)?;
        let name = match strings.get(name_idx) {
            Some(s) => s,
            None => continue,
        };
        let ns = match strings.get(ns_idx) {
            Some(s) => s,
            None => continue,
        };
        if name == TARGET_TYPE && ns == TARGET_NAMESPACE {
            c.skip(ctx.type_def_or_ref)?;
            c.skip(ctx.simple(T_FIELD))?;
            let method_list = c.read_index(ctx.simple(T_METHODDEF))?;
            found_type = Some((i, method_list));
            break;
        }
    }

    let (type_index, method_start) = found_type?;

    let method_end = if type_index + 1 < typedef_rows {
        let next_off = typedef_off + (type_index + 1) * typedef_row;
        let mut c = Cursor::new(data, next_off);
        c.skip(4 + ctx.string * 2 + ctx.type_def_or_ref + ctx.simple(T_FIELD))?;
        c.read_index(ctx.simple(T_METHODDEF))?
    } else {
        ctx.rows[T_METHODDEF as usize] as u32 + 1
    };

    let method_row = row_size(T_METHODDEF, &ctx)?;
    for m in method_start..method_end {
        let i = (m - 1) as usize;
        let row_off = methoddef_off + i * method_row;
        let mut c = Cursor::new(data, row_off);
        let rva = c.read_u32()?;
        c.skip(2 + 2)?;
        let name_idx = c.read_index(ctx.string)?;
        if strings.get(name_idx)? == TARGET_METHOD {
            return Some(rva);
        }
    }

    None
}

fn cli_metadata_rva(pe: &PeImage) -> Option<u32> {
    let data = pe.data();
    let start = pe.start();
    let pe_off = u32_at(data, start + 0x3C)? as usize;
    let opt = start + pe_off + 24;
    let magic = u16_at(data, opt)?;
    let data_dir_base = match magic {
        0x010B => opt + 96,
        0x020B => opt + 112,
        _ => return None,
    };
    let cli_rva = u32_at(data, data_dir_base + 14 * 8)?;
    let cli_off = pe.rva_to_file_offset(cli_rva)?;
    Some(u32_at(data, cli_off + 8)?)
}

struct Strings<'a> {
    bytes: &'a [u8],
}

impl<'a> Strings<'a> {
    fn get(&self, idx: u32) -> Option<&'a str> {
        if idx as usize >= self.bytes.len() {
            return None;
        }
        let end = self.bytes[idx as usize..]
            .iter()
            .position(|&b| b == 0)
            .map(|e| idx as usize + e)
            .unwrap_or(self.bytes.len());
        std::str::from_utf8(self.bytes.get(idx as usize..end)?).ok()
    }
}

struct Meta<'a> {
    strings: Option<Strings<'a>>,
    tables_body: usize,
    heap_sizes: u8,
    valid: u64,
    rows: [u32; 64],
}

impl<'a> Meta<'a> {
    fn parse(data: &'a [u8], abs: usize) -> Option<Meta<'a>> {
        let mut c = Cursor::new(data, abs);
        if c.read_u32()? != META_SIGNATURE {
            return None;
        }
        c.skip(2 + 2 + 4)?;
        let version_len = c.read_u32()? as usize;
        let version_len = (version_len + 3) & !3;
        c.skip(version_len)?;
        c.skip(2)?;
        let stream_count = c.read_u16()? as usize;

        let mut tables_off = None;
        let mut tables_size = None;
        let mut strings_off = None;
        let mut strings_size = None;
        let header_base = abs;

        for _ in 0..stream_count {
            let s_off = c.read_u32()? as usize;
            let s_size = c.read_u32()? as usize;
            let name_start = c.pos;
            let mut end = name_start;
            while end < data.len() && data[end] != 0 {
                end += 1;
            }
            let name = data.get(name_start..end)?;
            let name_len_with_null = end - name_start + 1;
            let padded = (name_len_with_null + 3) & !3;
            c.pos = name_start + padded;

            match name {
                b"#~" | b"#-" => {
                    tables_off = Some(header_base + s_off);
                    tables_size = Some(s_size);
                }
                b"#Strings" => {
                    strings_off = Some(header_base + s_off);
                    strings_size = Some(s_size);
                }
                _ => {}
            }
        }

        let _ = tables_size;
        let strings = match (strings_off, strings_size) {
            (Some(o), Some(s)) => Some(Strings {
                bytes: data.get(o..o + s)?,
            }),
            _ => None,
        };

        let tables_off = tables_off?;

        let mut c = Cursor::new(data, tables_off);
        c.skip(4 + 1 + 1)?;
        let heap_sizes = c.read_u8()?;
        c.skip(1)?;
        let valid = c.read_u64()?;
        c.skip(8)?;

        let mut rows = [0u32; 64];
        for t in 0..64u32 {
            if (valid >> t) & 1 == 1 {
                rows[t as usize] = c.read_u32()?;
            }
        }

        Some(Meta {
            strings,
            tables_body: c.pos,
            heap_sizes,
            valid,
            rows,
        })
    }
}

struct IndexCtx {
    string: usize,
    guid: usize,
    blob: usize,
    valid: u64,
    rows: [u32; 64],
    type_def_or_ref: usize,
    resolution_scope: usize,
}

impl IndexCtx {
    fn build(meta: &Meta) -> Option<Self> {
        let hs = meta.heap_sizes;
        let string = if hs & 0x01 != 0 { 4 } else { 2 };
        let guid = if hs & 0x02 != 0 { 4 } else { 2 };
        let blob = if hs & 0x04 != 0 { 4 } else { 2 };

        let r = meta.rows;
        let type_def_or_ref = coded_size(
            &[r[T_TYPEDEF as usize], r[T_TYPEREF as usize], r[T_TYPESPEC as usize]],
            2,
        );
        let resolution_scope = coded_size(
            &[
                r[T_MODULE as usize],
                r[T_MODULEREF as usize],
                r[T_ASSEMBLYREF as usize],
                r[T_TYPEREF as usize],
            ],
            2,
        );

        Some(IndexCtx {
            string,
            guid,
            blob,
            valid: meta.valid,
            rows: r,
            type_def_or_ref,
            resolution_scope,
        })
    }

    fn present(&self, t: u8) -> bool {
        (self.valid >> t) & 1 == 1
    }

    fn simple(&self, t: u8) -> usize {
        if self.rows[t as usize] >= 0x1_0000 {
            4
        } else {
            2
        }
    }
}

fn coded_size(rows: &[u32], tag_bits: u32) -> usize {
    let max = rows.iter().copied().max().unwrap_or(0);
    let threshold = 1u32 << (16 - tag_bits);
    if max >= threshold {
        4
    } else {
        2
    }
}

fn row_size(t: u8, ctx: &IndexCtx) -> Option<usize> {
    let s = ctx.string;
    let b = ctx.blob;
    let g = ctx.guid;
    Some(match t {
        T_MODULE => 2 + s + 3 * g,
        T_TYPEREF => ctx.resolution_scope + 2 * s,
        T_TYPEDEF => 4 + 2 * s + ctx.type_def_or_ref + ctx.simple(T_FIELD) + ctx.simple(T_METHODDEF),
        T_FIELDPTR => ctx.simple(T_FIELD),
        T_FIELD => 2 + s + b,
        T_METHODPTR => ctx.simple(T_METHODDEF),
        T_METHODDEF => 4 + 2 + 2 + s + b + ctx.simple(T_PARAM),
        _ => return None,
    })
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], pos: usize) -> Self {
        Cursor { data, pos }
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.pos = self.pos.checked_add(n)?;
        Some(())
    }

    fn read_u8(&mut self) -> Option<u8> {
        let v = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    fn read_u16(&mut self) -> Option<u16> {
        let v = u16::from_le_bytes(self.data.get(self.pos..self.pos + 2)?.try_into().ok()?);
        self.pos += 2;
        Some(v)
    }

    fn read_u32(&mut self) -> Option<u32> {
        let v = u32::from_le_bytes(self.data.get(self.pos..self.pos + 4)?.try_into().ok()?);
        self.pos += 4;
        Some(v)
    }

    fn read_u64(&mut self) -> Option<u64> {
        let v = u64::from_le_bytes(self.data.get(self.pos..self.pos + 8)?.try_into().ok()?);
        self.pos += 8;
        Some(v)
    }

    fn read_index(&mut self, width: usize) -> Option<u32> {
        match width {
            2 => self.read_u16().map(|v| v as u32),
            4 => self.read_u32(),
            _ => None,
        }
    }
}

fn u16_at(data: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?))
}

fn u32_at(data: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(pos..pos + 4)?.try_into().ok()?))
}
