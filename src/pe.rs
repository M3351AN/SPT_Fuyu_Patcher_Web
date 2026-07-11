// Copyright (c) 2025 渟雲. All rights reserved.
//
// Licensed under the TOSSRCU 2025.9 License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  https://raw.githubusercontent.com/M3351AN/M3351AN/9e7630a8511b8306c62952ca1a4f1ce0cc5b784a/LICENSE
//
// -----------------------------------------------------------------------------
// File: pe.rs
// Author: 渟雲(quq[at]outlook.it)
// Date: 2026-07-11
//
// -----------------------------------------------------------------------------
// PE/COFF parsing: locating embedded MZ images, detecting managed (CLI)
// assemblies, and resolving RVAs to raw file offsets.
// ----------------------------------------------------------------------------

const MZ_MAGIC: [u8; 2] = [0x4D, 0x5A];
const PE_SIGNATURE: u32 = 0x0000_4550;
const CLI_DATA_DIRECTORY_INDEX: usize = 14;

/// An MZ image found somewhere in the file.
#[derive(Clone, Copy)]
pub struct MzHeader {
    pub offset: usize,
}

#[derive(Clone, Copy)]
struct SectionHeader {
    virtual_address: u32,
    virtual_size: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
}

/// A parsed PE image rooted at `start` within `data`. The image only spans
/// `[start, start + pe_size)`; offsets returned by `rva_to_image_offset` are
/// relative to `start` and must be offset by `start()` to become absolute.
pub struct PeImage<'a> {
    data: &'a [u8],
    start: usize,
    pe_size: usize,
    managed: bool,
    sections: Vec<SectionHeader>,
}

impl<'a> PeImage<'a> {
    pub fn start(&self) -> usize {
        self.start
    }

    pub fn pe_size(&self) -> usize {
        self.pe_size
    }

    pub fn is_managed(&self) -> bool {
        self.managed
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Parse the PE image whose MZ header lives at `start` in `data`.
    pub fn parse(data: &'a [u8], start: usize) -> Option<Self> {
        let read_u16 = |off: usize| u16_from(data, start + off);
        let read_u32 = |off: usize| u32_from(data, start + off);

        if data.get(start..start + 2) != Some(&MZ_MAGIC) {
            return None;
        }

        let pe_off = read_u32(0x3C)? as usize;
        if read_u32(pe_off)? != PE_SIGNATURE {
            return None;
        }

        let coff = pe_off + 4;
        let num_sections = read_u16(coff + 2)?;
        let optional_header_size = read_u16(coff + 16)? as usize;

        let opt = pe_off + 24;
        let magic = read_u16(opt)?;
        // Data directories begin after the optional-header standard fields:
        // 96 bytes for PE32, 112 bytes for PE32+.
        let data_dir_base = match magic {
            0x010B => opt + 96,
            0x020B => opt + 112,
            _ => return None,
        };

        // CLI/CLR runtime header is data directory #14 (each entry is 8 bytes).
        let cli_rva = read_u32(data_dir_base + CLI_DATA_DIRECTORY_INDEX * 8)?;
        let cli_size = read_u32(data_dir_base + CLI_DATA_DIRECTORY_INDEX * 8 + 4)?;
        let managed = cli_rva != 0 && cli_size != 0;

        // Section table (40 bytes each) follows the optional header.
        let section_table = coff + 20 + optional_header_size;
        let mut sections = Vec::with_capacity(num_sections as usize);
        for i in 0..num_sections as usize {
            let s = section_table + i * 40;
            sections.push(SectionHeader {
                virtual_size: read_u32(s + 8)?,
                virtual_address: read_u32(s + 12)?,
                size_of_raw_data: read_u32(s + 16)?,
                pointer_to_raw_data: read_u32(s + 20)?,
            });
        }

        let pe_size = sections
            .iter()
            .map(|s| (s.pointer_to_raw_data + s.size_of_raw_data) as usize)
            .max()
            .unwrap_or(0);

        Some(PeImage {
            data,
            start,
            pe_size,
            managed,
            sections,
        })
    }

    /// Convert an RVA to an offset relative to the PE image start. Add `start()`
    /// for the absolute file offset.
    pub fn rva_to_image_offset(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size {
                return Some((rva - s.virtual_address + s.pointer_to_raw_data) as usize);
            }
        }
        None
    }

    /// Absolute file offset of `rva`.
    pub fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        self.rva_to_image_offset(rva)
            .map(|off| self.start + off)
    }
}

/// Scan the whole file for MZ images, keeping those whose parsed on-disk size
/// is plausible (>1KiB and within the file).
pub fn find_mz_headers(data: &[u8]) -> Vec<MzHeader> {
    let mut headers = Vec::new();
    let mut i = 0;
    while i + 64 <= data.len() {
        if data[i] == MZ_MAGIC[0] && data[i + 1] == MZ_MAGIC[1] {
            if let Some(img) = PeImage::parse(data, i) {
                let pe_size = img.pe_size();
                if pe_size > 1024 && i + pe_size <= data.len() {
                    headers.push(MzHeader { offset: i });
                }
            }
        }
        i += 1;
    }
    headers
}

fn u16_from(data: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?))
}

fn u32_from(data: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(pos..pos + 4)?.try_into().ok()?))
}
