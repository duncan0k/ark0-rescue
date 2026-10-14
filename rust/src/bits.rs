//! Bit strings (SPEC.md §1.2): bit i is bit (i mod 8) of byte (i div 8);
//! the unused high bits of the last byte are padding and must be zero.

#![forbid(unsafe_code)]

/// Bytes needed for `nbits` bits.
#[inline]
pub const fn nbytes(nbits: usize) -> usize {
    nbits.div_ceil(8)
}

/// True iff `data` is exactly `nbytes(nbits)` long and every padding bit is
/// zero.
pub fn is_canonical(data: &[u8], nbits: usize) -> bool {
    if data.len() != nbytes(nbits) {
        return false;
    }
    let used = nbits % 8;
    match data.last() {
        Some(&last) if used != 0 => last >> used == 0,
        _ => true,
    }
}

/// Clear the padding bits of a bit string of `nbits` bits held in
/// `nbytes(nbits)` bytes.
#[inline]
pub fn clear_padding(data: &mut [u8], nbits: usize) {
    let used = nbits % 8;
    if used != 0 {
        if let Some(last) = data.last_mut() {
            *last &= (1u8 << used) - 1;
        }
    }
}

/// Bits [start, start + nbits) of a bit string as an integer (nbits <= 128);
/// positions beyond the end of `data` read as zero.
pub fn load_bits(data: &[u8], start: usize, nbits: usize) -> u128 {
    debug_assert!(nbits <= 128);
    let off = start / 8;
    let sh = start % 8;
    let mut buf = [0u8; 17];
    if off < data.len() {
        let avail = (data.len() - off).min(17);
        buf[..avail].copy_from_slice(&data[off..off + avail]);
    }
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&buf[..16]);
    let mut v = u128::from_le_bytes(lo) >> sh;
    if sh != 0 {
        v |= (buf[16] as u128) << (128 - sh);
    }
    if nbits < 128 {
        v &= (1u128 << nbits) - 1;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_padding() {
        assert!(is_canonical(&[0x7f], 7));
        assert!(!is_canonical(&[0x80], 7));
        assert!(!is_canonical(&[0x00, 0x00], 7));
        assert!(is_canonical(&[0xff], 8));
        assert!(is_canonical(&[], 0));
        assert!(!is_canonical(&[0x00], 0));
        let mut b = [0xffu8; 3];
        clear_padding(&mut b, 17);
        assert_eq!(b, [0xff, 0xff, 0x01]);
    }

    #[test]
    fn load_bits_matches_big_integer_view() {
        let data: Vec<u8> = (0..40u32).map(|i| (i * 37 + 11) as u8).collect();
        // reference: bit i of the string
        let bit = |i: usize| -> u128 {
            if i / 8 < data.len() {
                ((data[i / 8] >> (i % 8)) & 1) as u128
            } else {
                0
            }
        };
        for start in [0usize, 1, 7, 8, 9, 63, 64, 100, 200, 250, 319, 320] {
            for nbits in [1usize, 7, 64, 87, 127, 128] {
                let mut expect = 0u128;
                for k in 0..nbits {
                    expect |= bit(start + k) << k;
                }
                assert_eq!(load_bits(&data, start, nbits), expect, "{start} {nbits}");
            }
        }
    }
}
