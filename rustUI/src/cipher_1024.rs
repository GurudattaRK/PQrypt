/// 1024-bit block cipher implementation in rust which is a direct port of the C implementation with identical logic

const MASK: [u32; 5] = [ // Bitmask table used for bit-level transpose
    0x55555555, // 0101... pattern for 1-bit swaps
    0x33333333, // 0011... pattern for 2-bit swaps
    0x0F0F0F0F, // 00001111... pattern for 4-bit swaps
    0x00FF00FF, // 8-bit lane swap mask
    0x0000FFFF, // 16-bit halfword swap mask
];

#[inline(always)]
fn rotate_left(w: u32, r: u32) -> u32 {
    w.rotate_left(r & 31)
}

#[inline(always)]
fn rotate_right(w: u32, r: u32) -> u32 {
    w.rotate_right(r & 31)
}

// Optimized transpose with better memory access patterns
fn transpose_grid_optimized(array: &mut [u32; 32]) {
    // Process in cache-friendly order with loop unrolling
    for d in 0..5 {
        let s = 1 << d;
        let m = MASK[d];
        let mut i = 0;
        
        // Unroll inner loops for better performance
        while i < 32 {
            match s {
                1 => {
                    // 1-bit swap - fully unrolled
                    let t = ((array[i] >> 1) ^ array[i + 1]) & m;
                    array[i] ^= t << 1;
                    array[i + 1] ^= t;
                    i += 2;
                },
                2 => {
                    // 2-bit swap - unrolled
                    for j in 0..2 {
                        let t = ((array[i + j] >> 2) ^ array[i + 2 + j]) & m;
                        array[i + j] ^= t << 2;
                        array[i + 2 + j] ^= t;
                    }
                    i += 4;
                },
                _ => {
                    // General case for larger swaps
                    for j in 0..s {
                        let t = ((array[i + j] >> s) ^ array[i + s + j]) & m;
                        array[i + j] ^= t << s;
                        array[i + s + j] ^= t;
                    }
                    i += 2 * s;
                }
            }
        }
    }
}

/// Encrypt a 1024-bit (128-byte) block using a 1024-bit key - faithful C port
pub fn encrypt_1024bit(input: &mut [u32; 32], key: &[u32; 32]) {
    let mut i = 0;
    
    while i < 32 {
        // First rotation pass - exactly match C logic
        let mut loop_idx = 0;
        while loop_idx < 32 {
            input[loop_idx] = rotate_left(input[loop_idx], key[i] + loop_idx as u32 + 32);
            loop_idx += 1;
            input[loop_idx] = rotate_right(input[loop_idx], key[i] + loop_idx as u32 + 32);
            loop_idx += 1;
        }
        i += 1;
        input[31] ^= key[i];
        i += 1;
        transpose_grid_optimized(input);
        
        // Second rotation pass - exactly match C logic
        let mut loop_idx = 0;
        while loop_idx < 32 {
            input[loop_idx] = rotate_left(input[loop_idx], key[i] + loop_idx as u32 + 32);
            loop_idx += 1;
            input[loop_idx] = rotate_right(input[loop_idx], key[i] + loop_idx as u32 + 32);
            loop_idx += 1;
        }
        i += 1;
        input[31] ^= key[i];
        i += 1;
        transpose_grid_optimized(input);
    }
}

/// Decrypt a 1024-bit (128-byte) block using a 1024-bit key - faithful C port
pub fn decrypt_1024bit(input: &mut [u32; 32], key: &[u32; 32]) {
    let mut i = 31;
    
    while i > 0 {
        transpose_grid_optimized(input);
        input[31] ^= key[i];
        if i > 0 { i -= 1; } else { break; }
        
        // Reverse second rotation pass - exactly match C logic
        let mut loop_idx = 0;
        while loop_idx < 32 {
            input[loop_idx] = rotate_right(input[loop_idx], key[i] + loop_idx as u32 + 32);
            loop_idx += 1;
            input[loop_idx] = rotate_left(input[loop_idx], key[i] + loop_idx as u32 + 32);
            loop_idx += 1;
        }
        if i > 0 { i -= 1; } else { break; }
        
        transpose_grid_optimized(input);
        input[31] ^= key[i];
        if i > 0 { i -= 1; } else { break; }
        
        // Reverse first rotation pass - exactly match C logic
        let mut loop_idx = 0;
        while loop_idx < 32 {
            input[loop_idx] = rotate_right(input[loop_idx], key[i] + loop_idx as u32 + 32);
            loop_idx += 1;
            input[loop_idx] = rotate_left(input[loop_idx], key[i] + loop_idx as u32 + 32);
            loop_idx += 1;
        }
        if i > 0 { i -= 1; } else { break; }
    }
}
