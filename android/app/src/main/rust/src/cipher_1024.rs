/// 1024-bit block cipher implementation in rust which is a direct port of the C implementation with identical logic

const MASK: [u32; 5] = [ // Bitmask table used for bit-level transpose
    0x55555555, // 0101... pattern for 1-bit swaps
    0x33333333, // 0011... pattern for 2-bit swaps
    0x0F0F0F0F, // 00001111... pattern for 4-bit swaps
    0x00FF00FF, // 8-bit lane swap mask
    0x0000FFFF, // 16-bit halfword swap mask
];

#[inline(always)]
fn rotate_left(w: u32, r: u32) -> u32 { // Rotate left with rotation masked to [0,31]
    w.rotate_left(r & 31) // Ensure rotate amount is within 32-bit word size
}

#[inline(always)]
fn rotate_right(w: u32, r: u32) -> u32 { // Rotate right with rotation masked to [0,31]
    w.rotate_right(r & 31) // Ensure rotate amount is within 32-bit word size
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

/// Encrypt a 1024-bit (128-byte) block using a 1024-bit key

pub fn encrypt_1024bit(input: &mut [u32; 32], key: &[u32; 32]) { // Feistel-like rounds using rotations and bit-transpose
    let mut i = 0; // Round index into key schedule
    while i < 32 { // 32 two-step subrounds (total 64 small ops per loop)
        let mut loop_idx = 0; // Process words pairwise
        while loop_idx < 32 { // For each of 32 words
            input[loop_idx] = rotate_left(input[loop_idx], key[i] + loop_idx as u32 + 32); // Left-rotate by key+index bias
            loop_idx += 1; // Next word
            input[loop_idx] = rotate_right(input[loop_idx], key[i] + loop_idx as u32 + 32); // Right-rotate next word
            loop_idx += 1; // Advance
        }
        i += 1; // Move to next key index
        input[31] ^= key[i]; // Inject key material into last word
        i += 1; // Advance key index
        transpose_grid_optimized(input); // Bitwise diffusion across words
        
        let mut loop_idx = 0; // Second half of the double-round
        while loop_idx < 32 { // Repeat pairwise rotations
            input[loop_idx] = rotate_left(input[loop_idx], key[i] + loop_idx as u32 + 32); // Left-rotate
            loop_idx += 1; // Next word
            input[loop_idx] = rotate_right(input[loop_idx], key[i] + loop_idx as u32 + 32); // Right-rotate
            loop_idx += 1; // Advance
        }
        i += 1; // Next key index
        input[31] ^= key[i]; // Mix in key again into last word
        i += 1; // Advance key index
        transpose_grid_optimized(input); // Further diffusion
    }
}

/// Decrypt a 1024-bit (128-byte) block using a 1024-bit key
pub fn decrypt_1024bit(input: &mut [u32; 32], key: &[u32; 32]) { // Inverse of encrypt_1024bit
    let mut i = 31; // Start from end of key schedule
    while i > 0 { // Walk backwards through subrounds
        transpose_grid_optimized(input); // Inverse transpose (same operation is self-inverse)
        input[31] ^= key[i]; // Undo key injection
        i -= 1; // Previous key index
        
        let mut loop_idx = 0; // Reverse pairwise rotations
        while loop_idx < 32 { // For each word
            input[loop_idx] = rotate_right(input[loop_idx], key[i] + loop_idx as u32 + 32); // Undo left-rotate
            loop_idx += 1; // Next word
            input[loop_idx] = rotate_left(input[loop_idx], key[i] + loop_idx as u32 + 32); // Undo right-rotate
            loop_idx += 1; // Advance
        }
        i -= 1; // Move back in key schedule
        
        transpose_grid_optimized(input); // Undo second transpose
        input[31] ^= key[i]; // Undo second key injection
        i -= 1; // Previous key
        
        let mut loop_idx = 0; // Reverse second half pairwise rotations
        while loop_idx < 32 { // For each word
            input[loop_idx] = rotate_right(input[loop_idx], key[i] + loop_idx as u32 + 32); // Undo left-rotate
            loop_idx += 1; // Next word
            input[loop_idx] = rotate_left(input[loop_idx], key[i] + loop_idx as u32 + 32); // Undo right-rotate
            loop_idx += 1; // Advance
        }
        if i > 0 { // Stop when we reach 0 to avoid underflow
            i -= 1; // Step further back
        }
    }
}
