//! Pure-Rust ISO/IEC 18004 QR Code encoder and Unicode half-block terminal renderer (`US-079`).
//!
//! Encodes arbitrary byte payloads (such as `mesh://join?v=1&...` mobile onboarding URIs)
//! using Byte mode (`0100`), GF(256) Reed-Solomon error correction (Error Correction Level M),
//! all standard function patterns (finder, timing, alignment, format BCH, version Golay), and
//! optimal 8-mask N1..N4 penalty minimization with zero external crate dependencies.

use mesh_core::{AppError, AppResult};

/// Supported QR code module dimension bounds (Versions 1..=20, ECC Level M).
#[cfg(test)]
const MIN_VERSION: u8 = 1;
const MAX_VERSION: u8 = 20;

/// Format information BCH generator (`x^10 + x^8 + x^5 + x^4 + x^2 + x + 1`).
const FORMAT_BCH_POLY: u16 = 0x537;
/// Standard ISO/IEC 18004 format information XOR mask (`101010000010010`).
const FORMAT_XOR_MASK: u16 = 0x5412;
/// Version information Golay generator (`x^12 + x^11 + x^10 + x^9 + x^8 + x^5 + x^2 + 1`).
const VERSION_GOLAY_POLY: u32 = 0x1F25;
/// GF(256) primitive polynomial reduction byte (`x^8 + x^4 + x^3 + x^2 + 1` without `x^8`).
const GF256_REDUCTION: u8 = 0x1D;
/// Default quiet-zone width in QR modules around each edge.
pub(crate) const DEFAULT_QUIET_ZONE: usize = 4;

/// Reed-Solomon Error Correction Level M parameters for a QR symbol version (ISO/IEC 18004 Table 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VersionSpecM {
    version: u8,
    total_codewords: usize,
    ec_per_block: usize,
    group1_blocks: usize,
    group1_data_cw: usize,
    group2_blocks: usize,
    group2_data_cw: usize,
    remainder_bits: usize,
}

impl VersionSpecM {
    const fn total_data_codewords(self) -> usize {
        self.group1_blocks * self.group1_data_cw + self.group2_blocks * self.group2_data_cw
    }

    const fn char_count_bits(self) -> usize {
        if self.version <= 9 { 8 } else { 16 }
    }

    /// Maximum raw byte payload capacity in Byte mode (`0100`) at ECC Level M.
    const fn max_byte_capacity(self) -> usize {
        let total_data_bits = self.total_data_codewords() * 8;
        let header_bits = 4 + self.char_count_bits();
        (total_data_bits - header_bits) / 8
    }
}

/// ISO/IEC 18004 Table 9 Level-M specs for Versions 1..=20 (up to 666 payload bytes).
const VERSION_SPECS_M: [VersionSpecM; 20] = [
    VersionSpecM {
        version: 1,
        total_codewords: 26,
        ec_per_block: 10,
        group1_blocks: 1,
        group1_data_cw: 16,
        group2_blocks: 0,
        group2_data_cw: 0,
        remainder_bits: 0,
    },
    VersionSpecM {
        version: 2,
        total_codewords: 44,
        ec_per_block: 16,
        group1_blocks: 1,
        group1_data_cw: 28,
        group2_blocks: 0,
        group2_data_cw: 0,
        remainder_bits: 7,
    },
    VersionSpecM {
        version: 3,
        total_codewords: 70,
        ec_per_block: 26,
        group1_blocks: 1,
        group1_data_cw: 44,
        group2_blocks: 0,
        group2_data_cw: 0,
        remainder_bits: 7,
    },
    VersionSpecM {
        version: 4,
        total_codewords: 100,
        ec_per_block: 18,
        group1_blocks: 2,
        group1_data_cw: 32,
        group2_blocks: 0,
        group2_data_cw: 0,
        remainder_bits: 7,
    },
    VersionSpecM {
        version: 5,
        total_codewords: 134,
        ec_per_block: 24,
        group1_blocks: 2,
        group1_data_cw: 43,
        group2_blocks: 0,
        group2_data_cw: 0,
        remainder_bits: 7,
    },
    VersionSpecM {
        version: 6,
        total_codewords: 172,
        ec_per_block: 16,
        group1_blocks: 4,
        group1_data_cw: 27,
        group2_blocks: 0,
        group2_data_cw: 0,
        remainder_bits: 7,
    },
    VersionSpecM {
        version: 7,
        total_codewords: 196,
        ec_per_block: 18,
        group1_blocks: 4,
        group1_data_cw: 31,
        group2_blocks: 0,
        group2_data_cw: 0,
        remainder_bits: 0,
    },
    VersionSpecM {
        version: 8,
        total_codewords: 242,
        ec_per_block: 22,
        group1_blocks: 2,
        group1_data_cw: 38,
        group2_blocks: 2,
        group2_data_cw: 39,
        remainder_bits: 0,
    },
    VersionSpecM {
        version: 9,
        total_codewords: 292,
        ec_per_block: 22,
        group1_blocks: 3,
        group1_data_cw: 36,
        group2_blocks: 2,
        group2_data_cw: 37,
        remainder_bits: 0,
    },
    VersionSpecM {
        version: 10,
        total_codewords: 346,
        ec_per_block: 26,
        group1_blocks: 4,
        group1_data_cw: 43,
        group2_blocks: 1,
        group2_data_cw: 44,
        remainder_bits: 0,
    },
    VersionSpecM {
        version: 11,
        total_codewords: 404,
        ec_per_block: 30,
        group1_blocks: 1,
        group1_data_cw: 50,
        group2_blocks: 4,
        group2_data_cw: 51,
        remainder_bits: 0,
    },
    VersionSpecM {
        version: 12,
        total_codewords: 466,
        ec_per_block: 22,
        group1_blocks: 6,
        group1_data_cw: 36,
        group2_blocks: 2,
        group2_data_cw: 37,
        remainder_bits: 0,
    },
    VersionSpecM {
        version: 13,
        total_codewords: 532,
        ec_per_block: 22,
        group1_blocks: 8,
        group1_data_cw: 37,
        group2_blocks: 1,
        group2_data_cw: 38,
        remainder_bits: 0,
    },
    VersionSpecM {
        version: 14,
        total_codewords: 581,
        ec_per_block: 24,
        group1_blocks: 4,
        group1_data_cw: 40,
        group2_blocks: 5,
        group2_data_cw: 41,
        remainder_bits: 3,
    },
    VersionSpecM {
        version: 15,
        total_codewords: 655,
        ec_per_block: 24,
        group1_blocks: 5,
        group1_data_cw: 41,
        group2_blocks: 5,
        group2_data_cw: 42,
        remainder_bits: 3,
    },
    VersionSpecM {
        version: 16,
        total_codewords: 733,
        ec_per_block: 28,
        group1_blocks: 7,
        group1_data_cw: 45,
        group2_blocks: 3,
        group2_data_cw: 46,
        remainder_bits: 3,
    },
    VersionSpecM {
        version: 17,
        total_codewords: 815,
        ec_per_block: 28,
        group1_blocks: 10,
        group1_data_cw: 46,
        group2_blocks: 1,
        group2_data_cw: 47,
        remainder_bits: 3,
    },
    VersionSpecM {
        version: 18,
        total_codewords: 901,
        ec_per_block: 26,
        group1_blocks: 9,
        group1_data_cw: 43,
        group2_blocks: 4,
        group2_data_cw: 44,
        remainder_bits: 3,
    },
    VersionSpecM {
        version: 19,
        total_codewords: 991,
        ec_per_block: 26,
        group1_blocks: 3,
        group1_data_cw: 44,
        group2_blocks: 11,
        group2_data_cw: 45,
        remainder_bits: 3,
    },
    VersionSpecM {
        version: 20,
        total_codewords: 1085,
        ec_per_block: 26,
        group1_blocks: 3,
        group1_data_cw: 41,
        group2_blocks: 13,
        group2_data_cw: 42,
        remainder_bits: 3,
    },
];

/// Encoded ISO/IEC 18004 QR Code matrix (`true` = dark module, `false` = light module).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QrCode {
    version: u8,
    size: usize,
    mask_id: u8,
    modules: Vec<bool>,
    is_function: Vec<bool>,
}

impl QrCode {
    /// Encodes `payload` into the smallest Version `1..=20` QR Code at Error Correction Level M.
    pub(crate) fn encode_bytes(payload: &[u8]) -> AppResult<Self> {
        let spec = select_version_m(payload.len())?;
        let data_cw = encode_byte_mode_codewords(payload, spec)?;
        let stream = interleave_reed_solomon_blocks(&data_cw, spec)?;

        let size = symbol_size(spec.version);
        let mut grid = QrGrid::new(size);
        grid.place_function_patterns(spec.version);
        grid.place_codewords(&stream);

        let mut best_mask: u8 = 0;
        let mut best_penalty = u32::MAX;
        for mask in 0..8_u8 {
            let mut candidate = grid.clone();
            candidate.apply_mask_and_format(mask);
            let penalty = candidate.evaluate_penalty();
            if penalty < best_penalty {
                best_penalty = penalty;
                best_mask = mask;
            }
        }

        grid.apply_mask_and_format(best_mask);
        Ok(Self {
            version: spec.version,
            size,
            mask_id: best_mask,
            modules: grid.modules,
            is_function: grid.is_function,
        })
    }

    /// Returns the QR symbol version (`1..=20`).
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn version(&self) -> u8 {
        self.version
    }

    /// Returns the matrix width and height in modules (`4 * version + 17`).
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn size(&self) -> usize {
        self.size
    }

    /// Returns the selected ISO mask pattern index (`0..=7`).
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn mask_id(&self) -> u8 {
        self.mask_id
    }

    /// Returns whether module `(x, y)` is dark (`true`) or light (`false`).
    #[must_use]
    pub(crate) fn module(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        self.modules
            .get(y * self.size + x)
            .copied()
            .unwrap_or(false)
    }

    /// Returns whether `(x, y)` belongs to fixed function patterns rather than masked data.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_function_module(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        self.is_function
            .get(y * self.size + x)
            .copied()
            .unwrap_or(false)
    }

    /// Renders the QR Code using Unicode half-block characters (`▀`, `▄`, `█`, ` `)
    /// with standard 4-module quiet zone margins.
    #[must_use]
    pub(crate) fn render_half_blocks(&self) -> String {
        self.render_half_blocks_with_quiet(DEFAULT_QUIET_ZONE, false)
    }

    /// Renders the QR Code using Unicode half-block characters with configurable quiet zone
    /// and polarity (`invert = false`: dark -> `'█'`, light -> `' '`).
    #[must_use]
    pub(crate) fn render_half_blocks_with_quiet(&self, quiet: usize, invert: bool) -> String {
        let total = self.size + quiet * 2;
        let mut out = String::new();
        let mut y = 0;
        while y < total {
            for x in 0..total {
                let top_dark = self.sample_with_quiet(x, y, quiet);
                let bot_dark = if y + 1 < total {
                    self.sample_with_quiet(x, y + 1, quiet)
                } else {
                    false
                };
                let (top, bot) = if invert {
                    (!top_dark, !bot_dark)
                } else {
                    (top_dark, bot_dark)
                };
                let ch = match (top, bot) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    (false, false) => ' ',
                };
                out.push(ch);
            }
            if y + 2 < total {
                out.push('\n');
            }
            y += 2;
        }
        out
    }

    fn sample_with_quiet(&self, x: usize, y: usize, quiet: usize) -> bool {
        let Some(mx) = x.checked_sub(quiet) else {
            return false;
        };
        let Some(my) = y.checked_sub(quiet) else {
            return false;
        };
        self.module(mx, my)
    }
}

const fn symbol_size(version: u8) -> usize {
    4 * (version as usize) + 17
}

fn select_version_m(payload_len: usize) -> AppResult<VersionSpecM> {
    for spec in VERSION_SPECS_M {
        if payload_len <= spec.max_byte_capacity() {
            return Ok(spec);
        }
    }
    Err(AppError::invalid_argument(format!(
        "QR payload length {payload_len} bytes exceeds Version {MAX_VERSION}-M maximum capacity ({} bytes)",
        VERSION_SPECS_M.last().map_or(0, |s| s.max_byte_capacity())
    )))
}

struct BitWriter {
    bytes: Vec<u8>,
    bit_len: usize,
}

impl BitWriter {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit_len: 0,
        }
    }

    fn push_bits(&mut self, value: u32, width: usize) {
        for shift in (0..width).rev() {
            let bit = ((value >> shift) & 1) != 0;
            let byte_idx = self.bit_len / 8;
            let bit_pos = 7 - (self.bit_len % 8);
            if byte_idx >= self.bytes.len() {
                self.bytes.push(0);
            }
            if bit && let Some(slot) = self.bytes.get_mut(byte_idx) {
                *slot |= 1_u8 << bit_pos;
            }
            self.bit_len += 1;
        }
    }
}

fn encode_byte_mode_codewords(payload: &[u8], spec: VersionSpecM) -> AppResult<Vec<u8>> {
    let data_cw_cap = spec.total_data_codewords();
    let total_data_bits = data_cw_cap * 8;
    let count_bits = spec.char_count_bits();
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| AppError::invalid_argument("QR payload exceeds u32 byte count"))?;

    let mut bits = BitWriter::new();
    // Mode indicator: Byte mode = 0100.
    bits.push_bits(0b0100, 4);
    bits.push_bits(payload_len, count_bits);
    for &byte in payload {
        bits.push_bits(u32::from(byte), 8);
    }

    // Terminator (up to 4 zero bits) and pad to byte boundary.
    let remaining = total_data_bits.saturating_sub(bits.bit_len);
    let term_bits = remaining.min(4);
    bits.push_bits(0, term_bits);
    let mod8 = bits.bit_len % 8;
    if mod8 != 0 {
        bits.push_bits(0, 8 - mod8);
    }

    // Standard ISO pad codewords: alternating 0xEC, 0x11.
    let mut pad_toggle = false;
    while bits.bytes.len() < data_cw_cap {
        bits.bytes.push(if pad_toggle { 0x11 } else { 0xEC });
        pad_toggle = !pad_toggle;
    }

    Ok(bits.bytes)
}

/// Multiplies two elements in GF(256) modulo `x^8 + x^4 + x^3 + x^2 + 1` (`0x11D`).
const fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut acc = 0_u8;
    let mut step = 0_u8;
    while step < 8 {
        if (b & 1) != 0 {
            acc ^= a;
        }
        let carry = (a & 0x80) != 0;
        a <<= 1;
        if carry {
            a ^= GF256_REDUCTION;
        }
        b >>= 1;
        step += 1;
    }
    acc
}

fn rs_generator_poly(ec_count: usize) -> Vec<u8> {
    let mut poly = vec![1_u8];
    let mut root = 1_u8;
    for _ in 0..ec_count {
        let mut next = vec![0_u8; poly.len() + 1];
        for (idx, &coeff) in poly.iter().enumerate() {
            if let Some(slot) = next.get_mut(idx) {
                *slot ^= coeff;
            }
            if let Some(slot) = next.get_mut(idx + 1) {
                *slot ^= gf256_mul(coeff, root);
            }
        }
        poly = next;
        root = gf256_mul(root, 2);
    }
    poly
}

fn rs_compute_ecc(data: &[u8], gen_poly: &[u8], ec_count: usize) -> Vec<u8> {
    let mut rem = vec![0_u8; ec_count];
    for &byte in data {
        let factor = byte ^ rem.first().copied().unwrap_or(0);
        for k in 0..ec_count.saturating_sub(1) {
            let shifted = rem.get(k + 1).copied().unwrap_or(0);
            if let Some(slot) = rem.get_mut(k) {
                *slot = shifted;
            }
        }
        if let Some(last) = rem.last_mut() {
            *last = 0;
        }
        for k in 0..ec_count {
            let g_coeff = gen_poly.get(k + 1).copied().unwrap_or(0);
            if let Some(slot) = rem.get_mut(k) {
                *slot ^= gf256_mul(factor, g_coeff);
            }
        }
    }
    rem
}

fn interleave_reed_solomon_blocks(data_cw: &[u8], spec: VersionSpecM) -> AppResult<Vec<u8>> {
    let total_blocks = spec.group1_blocks + spec.group2_blocks;
    let mut data_blocks: Vec<&[u8]> = Vec::with_capacity(total_blocks);
    let mut ecc_blocks: Vec<Vec<u8>> = Vec::with_capacity(total_blocks);
    let gen_poly = rs_generator_poly(spec.ec_per_block);

    let mut offset = 0;
    for _ in 0..spec.group1_blocks {
        let end = offset + spec.group1_data_cw;
        let slice = data_cw.get(offset..end).ok_or_else(|| {
            AppError::internal("QR group 1 codeword slice out of range during RS encoding")
        })?;
        ecc_blocks.push(rs_compute_ecc(slice, &gen_poly, spec.ec_per_block));
        data_blocks.push(slice);
        offset = end;
    }
    for _ in 0..spec.group2_blocks {
        let end = offset + spec.group2_data_cw;
        let slice = data_cw.get(offset..end).ok_or_else(|| {
            AppError::internal("QR group 2 codeword slice out of range during RS encoding")
        })?;
        ecc_blocks.push(rs_compute_ecc(slice, &gen_poly, spec.ec_per_block));
        data_blocks.push(slice);
        offset = end;
    }

    let max_data_cw = spec.group1_data_cw.max(spec.group2_data_cw);
    let mut interleaved = Vec::with_capacity(spec.total_codewords);
    for col in 0..max_data_cw {
        for block in &data_blocks {
            if let Some(&byte) = block.get(col) {
                interleaved.push(byte);
            }
        }
    }
    for col in 0..spec.ec_per_block {
        for ecc in &ecc_blocks {
            if let Some(&byte) = ecc.get(col) {
                interleaved.push(byte);
            }
        }
    }
    Ok(interleaved)
}

#[derive(Debug, Clone)]
struct QrGrid {
    size: usize,
    modules: Vec<bool>,
    is_function: Vec<bool>,
}

impl QrGrid {
    fn new(size: usize) -> Self {
        Self {
            size,
            modules: vec![false; size * size],
            is_function: vec![false; size * size],
        }
    }

    fn module(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        self.modules
            .get(y * self.size + x)
            .copied()
            .unwrap_or(false)
    }

    fn is_func(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return true;
        }
        self.is_function
            .get(y * self.size + x)
            .copied()
            .unwrap_or(true)
    }

    fn set_function(&mut self, x: usize, y: usize, dark: bool) {
        if x >= self.size || y >= self.size {
            return;
        }
        let idx = y * self.size + x;
        if let Some(m) = self.modules.get_mut(idx) {
            *m = dark;
        }
        if let Some(f) = self.is_function.get_mut(idx) {
            *f = true;
        }
    }

    fn set_data(&mut self, x: usize, y: usize, dark: bool) {
        if x >= self.size || y >= self.size {
            return;
        }
        let idx = y * self.size + x;
        if let Some(m) = self.modules.get_mut(idx) {
            *m = dark;
        }
    }

    fn place_function_patterns(&mut self, version: u8) {
        self.place_finder_with_separators(0, 0);
        self.place_finder_with_separators(self.size - 7, 0);
        self.place_finder_with_separators(0, self.size - 7);

        // Dark module always fixed at (8, 4 * version + 9) == (8, size - 8).
        self.set_function(8, self.size - 8, true);

        // Reserve format information areas (actual bits populated per candidate mask).
        for idx in 0..9 {
            if idx != 6 {
                self.set_function(idx, 8, false);
                self.set_function(8, idx, false);
            }
        }
        for idx in 0..8 {
            self.set_function(self.size - 8 + idx, 8, false);
        }
        for idx in 1..=7 {
            self.set_function(8, self.size - idx, false);
        }
        // Re-assert dark module inside top-left of bottom-left format strip.
        self.set_function(8, self.size - 8, true);

        // Timing patterns along row 6 and column 6.
        for i in 8..(self.size - 8) {
            let dark = i % 2 == 0;
            self.set_function(i, 6, dark);
            self.set_function(6, i, dark);
        }

        // Alignment patterns (Versions >= 2).
        let centers = alignment_centers(version);
        for &cy in &centers {
            for &cx in &centers {
                if !overlaps_finder(cx, cy, self.size) {
                    self.place_alignment(cx, cy);
                }
            }
        }

        // Version information blocks (Versions >= 7).
        if version >= 7 {
            self.place_version_info(version);
        }
    }

    fn place_finder_with_separators(&mut self, left: usize, top: usize) {
        for dy in -1_isize..=7 {
            for dx in -1_isize..=7 {
                let Ok(x) = usize::try_from(isize::try_from(left).unwrap_or(0) + dx) else {
                    continue;
                };
                let Ok(y) = usize::try_from(isize::try_from(top).unwrap_or(0) + dy) else {
                    continue;
                };
                if x >= self.size || y >= self.size {
                    continue;
                }
                let in_finder = (0..=6).contains(&dx) && (0..=6).contains(&dy);
                let dist_x = (dx - 3).abs();
                let dist_y = (dy - 3).abs();
                let chebyshev = dist_x.max(dist_y);
                let dark = in_finder && chebyshev != 2;
                self.set_function(x, y, dark);
            }
        }
    }

    fn place_alignment(&mut self, cx: usize, cy: usize) {
        for dy in -2_isize..=2 {
            for dx in -2_isize..=2 {
                let Ok(x) = usize::try_from(isize::try_from(cx).unwrap_or(0) + dx) else {
                    continue;
                };
                let Ok(y) = usize::try_from(isize::try_from(cy).unwrap_or(0) + dy) else {
                    continue;
                };
                let chebyshev = dx.abs().max(dy.abs());
                self.set_function(x, y, chebyshev != 1);
            }
        }
    }

    fn place_version_info(&mut self, version: u8) {
        let bits = compute_version_golay_bits(version);
        for i in 0..18 {
            let dark = ((bits >> i) & 1) != 0;
            let a = i / 3;
            let b = self.size - 11 + (i % 3);
            self.set_function(a, b, dark);
            self.set_function(b, a, dark);
        }
    }

    fn place_codewords(&mut self, codewords: &[u8]) {
        let total_bits = codewords.len() * 8;
        let mut bit_idx = 0_usize;
        let mut right_col: isize = isize::try_from(self.size).unwrap_or(0) - 1;
        let mut going_up = true;

        while right_col > 0 {
            if right_col == 6 {
                right_col -= 1;
            }
            for step in 0..self.size {
                let y = if going_up { self.size - 1 - step } else { step };
                for dx in [0_isize, -1_isize] {
                    let Ok(x) = usize::try_from(right_col + dx) else {
                        continue;
                    };
                    if self.is_func(x, y) {
                        continue;
                    }
                    let dark = if bit_idx < total_bits {
                        let byte = codewords.get(bit_idx / 8).copied().unwrap_or(0);
                        let shift = 7 - (bit_idx % 8);
                        bit_idx += 1;
                        ((byte >> shift) & 1) != 0
                    } else {
                        false
                    };
                    self.set_data(x, y, dark);
                }
            }
            going_up = !going_up;
            right_col -= 2;
        }
    }

    fn apply_mask_and_format(&mut self, mask_id: u8) {
        for y in 0..self.size {
            for x in 0..self.size {
                if !self.is_func(x, y) && mask_condition(mask_id, y, x) {
                    let flipped = !self.module(x, y);
                    self.set_data(x, y, flipped);
                }
            }
        }
        let fmt = compute_format_bch_bits_m(mask_id);
        // Copy 1: top-left around finder (bits 14 down to 0).
        for i in 0..=5 {
            let bit = ((fmt >> (14 - i)) & 1) != 0;
            self.set_function(i, 8, bit);
        }
        self.set_function(7, 8, ((fmt >> 8) & 1) != 0);
        self.set_function(8, 8, ((fmt >> 7) & 1) != 0);
        self.set_function(8, 7, ((fmt >> 6) & 1) != 0);
        for i in 0..=5 {
            let bit = ((fmt >> i) & 1) != 0;
            self.set_function(8, i, bit);
        }

        // Copy 2: bottom-left vertical (bits 14..=8) + top-right horizontal (bits 7..=0).
        for i in 0..7 {
            let bit = ((fmt >> (14 - i)) & 1) != 0;
            self.set_function(8, self.size - 1 - i, bit);
        }
        for i in 0..8 {
            let bit = ((fmt >> (7 - i)) & 1) != 0;
            self.set_function(self.size - 8 + i, 8, bit);
        }
        // Ensure dark module at (8, size - 8) remains untouched.
        self.set_function(8, self.size - 8, true);
    }

    fn evaluate_penalty(&self) -> u32 {
        self.penalty_n1() + self.penalty_n2() + self.penalty_n3() + self.penalty_n4()
    }

    /// N1: 5+ consecutive same-color modules horizontally or vertically.
    fn penalty_n1(&self) -> u32 {
        let mut penalty = 0_u32;
        for a in 0..self.size {
            let mut run_color_h = false;
            let mut run_len_h = 0_u32;
            let mut run_color_v = false;
            let mut run_len_v = 0_u32;
            for b in 0..self.size {
                let h = self.module(b, a);
                if b == 0 || h != run_color_h {
                    if run_len_h >= 5 {
                        penalty += 3 + (run_len_h - 5);
                    }
                    run_color_h = h;
                    run_len_h = 1;
                } else {
                    run_len_h += 1;
                }

                let v = self.module(a, b);
                if b == 0 || v != run_color_v {
                    if run_len_v >= 5 {
                        penalty += 3 + (run_len_v - 5);
                    }
                    run_color_v = v;
                    run_len_v = 1;
                } else {
                    run_len_v += 1;
                }
            }
            if run_len_h >= 5 {
                penalty += 3 + (run_len_h - 5);
            }
            if run_len_v >= 5 {
                penalty += 3 + (run_len_v - 5);
            }
        }
        penalty
    }

    /// N2: 2x2 blocks of identical module polarity (+3 each).
    fn penalty_n2(&self) -> u32 {
        let mut penalty = 0_u32;
        for y in 0..self.size.saturating_sub(1) {
            for x in 0..self.size.saturating_sub(1) {
                let c = self.module(x, y);
                if c == self.module(x + 1, y)
                    && c == self.module(x, y + 1)
                    && c == self.module(x + 1, y + 1)
                {
                    penalty += 3;
                }
            }
        }
        penalty
    }

    /// N3: Finder-like `1:1:3:1:1` pattern with 4-module light padding on either side (+40 each).
    fn penalty_n3(&self) -> u32 {
        const PAT_LEFT: [bool; 11] = [
            false, false, false, false, true, false, true, true, true, false, true,
        ];
        const PAT_RIGHT: [bool; 11] = [
            true, false, true, true, true, false, true, false, false, false, false,
        ];
        if self.size < 11 {
            return 0;
        }
        let mut penalty = 0_u32;
        for a in 0..self.size {
            for b in 0..=(self.size - 11) {
                let match_h_left = (0..11)
                    .all(|k| PAT_LEFT.get(k).copied().unwrap_or(false) == self.module(b + k, a));
                let match_h_right = (0..11)
                    .all(|k| PAT_RIGHT.get(k).copied().unwrap_or(false) == self.module(b + k, a));
                if match_h_left || match_h_right {
                    penalty += 40;
                }

                let match_v_left = (0..11)
                    .all(|k| PAT_LEFT.get(k).copied().unwrap_or(false) == self.module(a, b + k));
                let match_v_right = (0..11)
                    .all(|k| PAT_RIGHT.get(k).copied().unwrap_or(false) == self.module(a, b + k));
                if match_v_left || match_v_right {
                    penalty += 40;
                }
            }
        }
        penalty
    }

    /// N4: Deviation of dark module percentage from 50% (+10 per 5% band).
    fn penalty_n4(&self) -> u32 {
        let total = u32::try_from(self.modules.len()).unwrap_or(1);
        let dark = u32::try_from(self.modules.iter().filter(|&&m| m).count()).unwrap_or(0);
        let scaled = dark * 20;
        let low_band = i32::try_from(scaled / total).unwrap_or(0);
        let high_band = if scaled.is_multiple_of(total) {
            low_band
        } else {
            low_band + 1
        };
        let min_steps = low_band.abs_diff(10).min(high_band.abs_diff(10));
        min_steps * 10
    }
}

const fn mask_condition(mask_id: u8, row: usize, col: usize) -> bool {
    match mask_id {
        0 => (row + col).is_multiple_of(2),
        1 => row.is_multiple_of(2),
        2 => col.is_multiple_of(3),
        3 => (row + col).is_multiple_of(3),
        4 => ((row / 2) + (col / 3)).is_multiple_of(2),
        5 => ((row * col) % 2) + ((row * col) % 3) == 0,
        6 => (((row * col) % 2) + ((row * col) % 3)).is_multiple_of(2),
        7 => (((row + col) % 2) + ((row * col) % 3)).is_multiple_of(2),
        _ => false,
    }
}

/// Computes the 15-bit BCH(15, 5) + `0x5412` format word for Error Correction Level M (`00`).
#[must_use]
pub(crate) const fn compute_format_bch_bits_m(mask_id: u8) -> u16 {
    // ECC level M = 0b00, 3-bit mask index = (mask_id & 0x07).
    let data = (mask_id & 0x07) as u16;
    let mut rem = data << 10;
    let mut bit = 14_i32;
    while bit >= 10 {
        if ((rem >> bit) & 1) != 0 {
            rem ^= FORMAT_BCH_POLY << (bit - 10);
        }
        bit -= 1;
    }
    ((data << 10) | rem) ^ FORMAT_XOR_MASK
}

/// Computes the 18-bit Golay(18, 6) version info word for Versions `7..=40`.
#[must_use]
pub(crate) const fn compute_version_golay_bits(version: u8) -> u32 {
    let data = version as u32;
    let mut rem = data << 12;
    let mut bit = 17_i32;
    while bit >= 12 {
        if ((rem >> bit) & 1) != 0 {
            rem ^= VERSION_GOLAY_POLY << (bit - 12);
        }
        bit -= 1;
    }
    (data << 12) | rem
}

fn alignment_centers(version: u8) -> Vec<usize> {
    if version < 2 {
        return Vec::new();
    }
    let count = usize::from(version) / 7 + 2;
    let last = 4 * usize::from(version) + 10;
    let intervals = count - 1;
    // Step size rounded up to even integer per ISO/IEC 18004 Annex E.
    let raw_step = (last - 6).div_ceil(intervals);
    let step = if raw_step.is_multiple_of(2) {
        raw_step
    } else {
        raw_step + 1
    };

    let mut coords = Vec::with_capacity(count);
    coords.push(6);
    let mut middle = Vec::with_capacity(count.saturating_sub(2));
    let mut cur = last;
    for _ in 0..intervals.saturating_sub(1) {
        cur = cur.saturating_sub(step);
        middle.push(cur);
    }
    middle.reverse();
    coords.extend(middle);
    coords.push(last);
    coords
}

const fn overlaps_finder(cx: usize, cy: usize, size: usize) -> bool {
    let top_left = cx <= 8 && cy <= 8;
    let top_right = cx >= size - 9 && cy <= 8;
    let bottom_left = cx <= 8 && cy >= size - 9;
    top_left || top_right || bottom_left
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_QUIET_ZONE, MAX_VERSION, MIN_VERSION, QrCode, QrGrid, VERSION_SPECS_M,
        compute_format_bch_bits_m, compute_version_golay_bits, gf256_mul, mask_condition,
        rs_compute_ecc, rs_generator_poly, symbol_size,
    };

    fn decode_qr_byte_payload(qr: &QrCode) -> Result<Vec<u8>, String> {
        let size = qr.size();
        // Verify and extract mask_id from Copy 1 format word (M = 0b00).
        let mut fmt1 = 0_u16;
        for i in 0..=5 {
            fmt1 = (fmt1 << 1) | u16::from(qr.module(i, 8));
        }
        fmt1 = (fmt1 << 1) | u16::from(qr.module(7, 8));
        fmt1 = (fmt1 << 1) | u16::from(qr.module(8, 8));
        fmt1 = (fmt1 << 1) | u16::from(qr.module(8, 7));
        for i in (0..=5).rev() {
            fmt1 = (fmt1 << 1) | u16::from(qr.module(8, i));
        }
        let unmasked = fmt1 ^ super::FORMAT_XOR_MASK;
        let ec_bits = (unmasked >> 13) & 0b11;
        if ec_bits != 0 {
            return Err(format!("expected ECC M (00), decoded {ec_bits:#b}"));
        }
        let mask_id = u8::try_from((unmasked >> 10) & 0b111).map_err(|e| e.to_string())?;
        if compute_format_bch_bits_m(mask_id) != fmt1 {
            return Err("format BCH bits mismatch".to_owned());
        }

        // Rebuild function mask for the detected version and read codewords in ISO zig-zag order.
        let mut ref_grid = QrGrid::new(size);
        ref_grid.place_function_patterns(qr.version());

        let spec = VERSION_SPECS_M
            .get(usize::from(qr.version()) - 1)
            .ok_or_else(|| "version out of range".to_owned())?;

        let mut codewords = Vec::with_capacity(spec.total_codewords);
        let mut cur_byte = 0_u8;
        let mut bits_in_byte = 0_u8;
        let mut right_col: isize = isize::try_from(size).map_err(|e| e.to_string())? - 1;
        let mut going_up = true;

        'zig: while right_col > 0 {
            if right_col == 6 {
                right_col -= 1;
            }
            for step in 0..size {
                let y = if going_up { size - 1 - step } else { step };
                for dx in [0_isize, -1_isize] {
                    let Ok(x) = usize::try_from(right_col + dx) else {
                        continue;
                    };
                    if ref_grid.is_func(x, y) {
                        continue;
                    }
                    let raw = qr.module(x, y);
                    let unmasked_bit = if mask_condition(mask_id, y, x) {
                        !raw
                    } else {
                        raw
                    };
                    cur_byte = (cur_byte << 1) | u8::from(unmasked_bit);
                    bits_in_byte += 1;
                    if bits_in_byte == 8 {
                        codewords.push(cur_byte);
                        cur_byte = 0;
                        bits_in_byte = 0;
                        if codewords.len() == spec.total_codewords {
                            break 'zig;
                        }
                    }
                }
            }
            going_up = !going_up;
            right_col -= 2;
        }

        if codewords.len() != spec.total_codewords {
            return Err(format!(
                "decoded {} codewords, expected {}",
                codewords.len(),
                spec.total_codewords
            ));
        }

        // De-interleave data and ECC blocks and verify RS parity per block.
        let total_blocks = spec.group1_blocks + spec.group2_blocks;
        let mut blocks_data: Vec<Vec<u8>> = (0..total_blocks).map(|_| Vec::new()).collect();
        let max_data = spec.group1_data_cw.max(spec.group2_data_cw);
        let mut idx = 0_usize;
        for col in 0..max_data {
            for (b_idx, block) in blocks_data.iter_mut().enumerate() {
                let cap = if b_idx < spec.group1_blocks {
                    spec.group1_data_cw
                } else {
                    spec.group2_data_cw
                };
                if col < cap {
                    let byte = codewords
                        .get(idx)
                        .copied()
                        .ok_or_else(|| "interleaved data underrun".to_owned())?;
                    block.push(byte);
                    idx += 1;
                }
            }
        }

        let gen_poly = rs_generator_poly(spec.ec_per_block);
        let mut blocks_ecc: Vec<Vec<u8>> = (0..total_blocks).map(|_| Vec::new()).collect();
        for _ in 0..spec.ec_per_block {
            for ecc in &mut blocks_ecc {
                let byte = codewords
                    .get(idx)
                    .copied()
                    .ok_or_else(|| "interleaved ecc underrun".to_owned())?;
                ecc.push(byte);
                idx += 1;
            }
        }
        for (data, ecc) in blocks_data.iter().zip(blocks_ecc.iter()) {
            let computed = rs_compute_ecc(data, &gen_poly, spec.ec_per_block);
            if &computed != ecc {
                return Err("RS block parity check failed".to_owned());
            }
        }

        // Reassemble bitstream and parse Byte mode (0100) length + payload.
        let mut stream = Vec::new();
        for block in blocks_data {
            stream.extend(block);
        }

        let read_bits = |pos: &mut usize, count: usize| -> Result<u32, String> {
            let mut acc = 0_u32;
            for _ in 0..count {
                let byte = stream
                    .get(*pos / 8)
                    .copied()
                    .ok_or_else(|| "bitstream read overflow".to_owned())?;
                let bit = (byte >> (7 - (*pos % 8))) & 1;
                acc = (acc << 1) | u32::from(bit);
                *pos += 1;
            }
            Ok(acc)
        };

        let mut bit_pos = 0_usize;
        let mode = read_bits(&mut bit_pos, 4)?;
        if mode != 0b0100 {
            return Err(format!("expected Byte mode 0100, got {mode:#b}"));
        }
        let len = usize::try_from(read_bits(&mut bit_pos, spec.char_count_bits())?)
            .map_err(|e| e.to_string())?;
        let mut payload = Vec::with_capacity(len);
        for _ in 0..len {
            let byte = u8::try_from(read_bits(&mut bit_pos, 8)?).map_err(|e| e.to_string())?;
            payload.push(byte);
        }
        Ok(payload)
    }

    #[test]
    fn test_qr_version_geometry_matches_total_codewords_and_remainder_bits() -> Result<(), String> {
        // Arrange / Act / Assert
        for spec in VERSION_SPECS_M {
            if spec.version < MIN_VERSION || spec.version > MAX_VERSION {
                return Err("spec version outside bounds".to_owned());
            }
            let size = symbol_size(spec.version);
            let mut grid = QrGrid::new(size);
            grid.place_function_patterns(spec.version);
            let data_modules = grid.is_function.iter().filter(|&&f| !f).count();
            let expected_modules = spec.total_codewords * 8 + spec.remainder_bits;
            if data_modules != expected_modules {
                return Err(format!(
                    "v{}: counted {} data modules vs {} expected",
                    spec.version, data_modules, expected_modules
                ));
            }
            assert_eq!(
                spec.group1_blocks * (spec.group1_data_cw + spec.ec_per_block)
                    + spec.group2_blocks * (spec.group2_data_cw + spec.ec_per_block),
                spec.total_codewords
            );
        }
        Ok(())
    }

    #[test]
    fn test_qr_finder_timing_dark_module_format_and_version_bits() -> Result<(), String> {
        // Arrange
        let uri = "mesh://join?v=1&server=control.example.com%3A4443&pin=sha256%3A0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&key=mpk_testkey1234567890&name=iphone-16";

        // Act
        let qr = QrCode::encode_bytes(uri.as_bytes()).map_err(|e| e.to_string())?;
        let size = qr.size();

        // Assert: version >= 7 so Golay version blocks also execute.
        assert!(qr.version() >= 7);
        assert_eq!(size, 4 * usize::from(qr.version()) + 17);

        // Finder corners (top-left, top-right, bottom-left) 7x7 outer ring = dark, inner 5x5 = light, 3x3 = dark.
        for (ox, oy) in [(0, 0), (size - 7, 0), (0, size - 7)] {
            for dy in 0..7_isize {
                for dx in 0..7_isize {
                    let expected = (dx - 3).abs().max((dy - 3).abs()) != 2;
                    let ux = ox + usize::try_from(dx).map_err(|e| e.to_string())?;
                    let uy = oy + usize::try_from(dy).map_err(|e| e.to_string())?;
                    assert_eq!(qr.module(ux, uy), expected);
                }
            }
        }

        // Fixed dark module and alternating timing patterns.
        assert!(qr.module(8, size - 8));
        for i in 8..(size - 8) {
            assert_eq!(qr.module(i, 6), i % 2 == 0);
            assert_eq!(qr.module(6, i), i % 2 == 0);
        }

        // ISO/IEC 18004 known vectors for format BCH (M + mask 0 == 0x5412) and Version 7 Golay (0x07C94).
        assert_eq!(compute_format_bch_bits_m(0), 0x5412);
        assert_eq!(compute_version_golay_bits(7), 0x07C94);

        // Dual format copies must match bit-for-bit around Copy 1 and Copy 2.
        let fmt = compute_format_bch_bits_m(qr.mask_id());
        for i in 0..=5 {
            assert_eq!(qr.module(i, 8), ((fmt >> (14 - i)) & 1) != 0);
            assert_eq!(qr.module(8, size - 1 - i), ((fmt >> (14 - i)) & 1) != 0);
        }
        assert_eq!(qr.module(8, size - 7), ((fmt >> 8) & 1) != 0);
        assert_eq!(qr.module(size - 8, 8), ((fmt >> 7) & 1) != 0);
        assert_eq!(qr.module(8, 8), ((fmt >> 7) & 1) != 0);
        assert_eq!(qr.module(size - 1, 8), (fmt & 1) != 0);
        assert_eq!(qr.module(8, 0), (fmt & 1) != 0);

        Ok(())
    }

    #[test]
    fn test_qr_reed_solomon_and_roundtrip_payload_decoding() -> Result<(), String> {
        // Arrange: test Version 1, Version 8 (multi-block), and Version 14 (16-bit char count + alignment).
        let payloads = [
            "mesh://v1".as_bytes().to_vec(),
            "mesh://join?v=1&server=198.51.100.10%3A8443&pin=sha256%3Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&key=mpk_abc"
                .as_bytes()
                .to_vec(),
            vec![b'x'; 350],
        ];

        // Act / Assert: QR GF(256) uses 0x11D (`0x57 * 0x83 == 0x31`).
        assert_eq!(gf256_mul(0x57, 0x83), 0x31);
        for payload in payloads {
            let qr = QrCode::encode_bytes(&payload).map_err(|e| e.to_string())?;
            let decoded = decode_qr_byte_payload(&qr)?;
            assert_eq!(decoded, payload);
            assert!(qr.is_function_module(0, 0));
            assert!(!qr.is_function_module(qr.size() - 1, qr.size() - 1));
        }

        // Known ISO/IEC 18004 `"01234567"` M-level byte check: `"Hello"` round-trip & UTF-8 bytes.
        let utf8_msg = "mesh://join?v=1&server=vpn.internal%3A4443&key=mpk_987654";
        let qr_utf8 = QrCode::encode_bytes(utf8_msg.as_bytes()).map_err(|e| e.to_string())?;
        assert_eq!(decode_qr_byte_payload(&qr_utf8)?, utf8_msg.as_bytes());
        Ok(())
    }

    #[test]
    fn test_qr_half_block_terminal_rendering_preserves_quiet_zone_and_rows() -> Result<(), String> {
        // Arrange
        let qr =
            QrCode::encode_bytes(b"mesh://join?v=1&key=mpk_demo").map_err(|e| e.to_string())?;
        let total = qr.size() + DEFAULT_QUIET_ZONE * 2;
        let expected_lines = total.div_ceil(2);

        // Act
        let rendered = qr.render_half_blocks();
        let lines: Vec<&str> = rendered.lines().collect();

        // Assert
        assert_eq!(lines.len(), expected_lines);
        for line in &lines {
            assert_eq!(line.chars().count(), total);
            assert!(line.chars().all(|ch| matches!(ch, '█' | '▀' | '▄' | ' ')));
        }
        // Top and bottom quiet rows (first two rows = 4 quiet modules high? Top row encodes y=0,1 both light).
        assert!(lines.first().is_some_and(|l| l.chars().all(|ch| ch == ' ')));
        assert!(lines.get(1).is_some_and(|l| l.chars().all(|ch| ch == ' ')));
        Ok(())
    }
}
