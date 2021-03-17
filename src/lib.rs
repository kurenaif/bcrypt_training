// references
// https://www.schneier.com/wp-content/uploads/2015/12/constants-2.txt
// https://link.springer.com/chapter/10.1007/3-540-58108-1_24#:~:text=Blowfish%2C%20a%20new%20secret%2Dkey%20block%20cipher%2C%20is%20proposed.&text=The%20block%20size%20is%2064,very%20efficient%20on%20large%20microprocessors.
// https://en.wikipedia.org/wiki/Blowfish_(cipher)
// https://ja.wikipedia.org/wiki/Bcrypt
// https://github.com/libressl-portable/openbsd/blob/master/src/lib/libc/crypt/bcrypt.c
// https://github.com/golang/crypto/blob/5ea612d1eb830b38bc4e914e37f55311eb58adce/blowfish/block.go#L71

mod consts;

use std::mem::swap;

pub struct State {
    pub s0: [u32; 256],
    pub s1: [u32; 256],
    pub s2: [u32; 256],
    pub s3: [u32; 256],
    pub p: [u32; 18],
}

pub fn bcrypt(cost: u32, salt: &[u8; 16], password: &[u8]) {
    let state = eks_blowfish_setup(cost, salt, password);
    let ctext = "OrpheanBeholderScryDoubt".as_bytes();

    for _ in 0..64 {
        let mut pos = 0usize;
        // encrypt with ecb
        encrypt(&state, get_next_u64(ctext, &mut pos).unwrap());
        encrypt(&state, get_next_u64(ctext, &mut pos).unwrap());
        encrypt(&state, get_next_u64(ctext, &mut pos).unwrap());
    }

    format!("$2a${}${:?}",cost, ctext);
    // TODO: テストとctext
}

pub fn eks_blowfish_setup(cost: u32, salt: &[u8; 16], password: &[u8]) -> State {
    // InitialState
    let mut state = State {
        s0: consts::SBOX0,
        s1: consts::SBOX1,
        s2: consts::SBOX2,
        s3: consts::SBOX3,
        p: consts::PARRAY
    };

    expand_key(&mut state, salt, password);
    for _ in 0..(1<<cost) {
        expand_key_without_salt(&mut state, password);
        expand_key_without_salt(&mut state, salt);
    }

    return state
}

/// Extracts 4 bytes from the byte string and converts it to u32. ( If there are not enough bytes, it loops to the first byte. )
///
/// # Arguments
///
/// * `from` - byte array for converting
/// * `pos` - start position for converting
///
/// # Example
///
/// ```
/// use kurebcrypt::*;
/// let byte_array: [u8; 3] = [1, 2, 3];
/// let mut j: usize = 0;
/// let res = get_next_u32(&byte_array, &mut j);
/// assert_eq!(res, Some(0x01020301));
/// assert_eq!(j, 1);
/// ```
pub fn get_next_u32(from: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos >= from.len() {
        return None
    }

    let mut res: u32 = 0;
    for _ in 0..4 {
        res = res << 8 | (from[*pos] as u32);
        *pos += 1;
        if *pos >= from.len() {
            *pos = 0
        }
    }
    Some(res)
}

pub fn get_next_u64(from: &[u8], pos: &mut usize) -> Option<u64> {
    let u64salt_lo = match get_next_u32(from, pos) {
        Some(x) => x as u64,
        None => return None
    };

    let u64salt_hi = match get_next_u32(from, pos) {
        Some(x) => x as u64,
        None => return None
    };
    return Some(u64salt_lo | u64salt_hi);
}


pub fn split_u64_to_u32(from: u64) -> (u32, u32) {
    let lo = from as u32;
    let hi = (from >> 32) as u32;
    return (lo, hi)
}

// Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish) pp.195
pub fn encrypt(state: &State, data: u64) -> u64 {
    let mut pos = 0usize;
    let mut xl = data as u32;
    let mut xr = (data >> 32) as u32;

    for i in 0..state.p.len() {
        xl = xl ^ state.p[i];
        xr = f(state, xl) ^ xr;
        swap(&mut xl, &mut xr);
    }
    swap(&mut xl, &mut xr);
    xr = xr ^ state.p[16];
    xl = xl ^ state.p[17];

    (xl as u64) | (xr as u64) << 32
}

fn f(state: &State, x: u32) -> u32 {
    let a = x as u8;
    let b = (x >> 8) as u8;
    let c = (x >> 16) as u8;
    let d = (x >> 24) as u8;
    ((state.s0[a as usize].wrapping_add(state.s1[b as usize])) ^ state.s2[c as usize]).wrapping_add(state.s3[d as usize])
}

pub fn expand_key(state: &mut State, salt: &[u8; 16], password: &[u8]) -> Result<(),&'static str> {
    if password.len() < 1 {
        return Err("password must be at least 1 characters")
    }
    if password.len() > 72 {
        return Err("password must be a string with a maximum length of 72")
    }

    {
        let mut pos = 0usize;
        for i in 0..state.p.len() {
            let word = match get_next_u32(password, &mut pos) {
                Some(x) => x,
                None => return Err("unknown error")
            };
            state.p[i] = state.p[i] ^ word;
        }
    }

    let mut salt_pos = 0;
    let mut block = encrypt(state, get_next_u64(salt, &mut salt_pos).unwrap());
    let (block_lo, block_hi) = split_u64_to_u32(block);
    state.p[0] = block_lo;
    state.p[1] = block_hi;

    for i in 1..9 {
        block = encrypt(&state, block ^ get_next_u64(salt, &mut salt_pos).unwrap());
        let (block_lo, block_hi) = split_u64_to_u32(block);
        state.p[i*2] = block_lo;
        state.p[i*2 + 1] = block_hi;
    }

    for n in 0..128 {
        block = encrypt(&state, block ^ get_next_u64(salt, &mut salt_pos).unwrap());
        let (block_lo, block_hi) = split_u64_to_u32(block);
        state.s0[n*2] = block_lo;
        state.s0[n*2+1] = block_hi;
    }

    for n in 0..128 {
        block = encrypt(&state, block ^ get_next_u64(salt, &mut salt_pos).unwrap());
        let (block_lo, block_hi) = split_u64_to_u32(block);
        state.s1[n*2] = block_lo;
        state.s1[n*2+1] = block_hi;
    }

    for n in 0..128 {
        block = encrypt(&state, block ^ get_next_u64(salt, &mut salt_pos).unwrap());
        let (block_lo, block_hi) = split_u64_to_u32(block);
        state.s2[n*2] = block_lo;
        state.s2[n*2+1] = block_hi;
    }

    for n in 0..128 {
        block = encrypt(&state, block ^ get_next_u64(salt, &mut salt_pos).unwrap());
        let (block_lo, block_hi) = split_u64_to_u32(block);
        state.s3[n*2] = block_lo;
        state.s3[n*2+1] = block_hi;
    }

    Ok(())
}

pub fn expand_key_without_salt(state: &mut State, password: &[u8]) -> Result<(),&'static str> {
    if password.len() < 1 {
        return Err("password must be at least 1 characters")
    }
    if password.len() > 72 {
        return Err("password must be a string with a maximum length of 72")
    }

    {
        let mut pos = 0usize;
        for i in 0..state.p.len() {
            let word = match get_next_u32(password, &mut pos) {
                Some(x) => x,
                None => return Err("unknown error")
            };
            state.p[i] = state.p[i] ^ word;
        }
    }

    let mut block = encrypt(state, 0);
    let (block_lo, block_hi) = split_u64_to_u32(block);
    state.p[0] = block_lo;
    state.p[1] = block_hi;

    for i in 0..9 {
        block = encrypt(&state, block);
        let (block_lo, block_hi) = split_u64_to_u32(block);
        state.p[i*2] = block_lo;
        state.p[i*2 + 1] = block_hi;
    }

    for n in 0..128 {
        block = encrypt(&state, block);
        let (block_lo, block_hi) = split_u64_to_u32(block);
        state.s0[n*2] = block_lo;
        state.s0[n*2+1] = block_hi;
    }

    for n in 0..128 {
        block = encrypt(&state, block);
        let (block_lo, block_hi) = split_u64_to_u32(block);
        state.s1[n*2] = block_lo;
        state.s1[n*2+1] = block_hi;
    }

    for n in 0..128 {
        block = encrypt(&state, block);
        let (block_lo, block_hi) = split_u64_to_u32(block);
        state.s2[n*2] = block_lo;
        state.s2[n*2+1] = block_hi;
    }

    for n in 0..128 {
        block = encrypt(&state, block);
        let (block_lo, block_hi) = split_u64_to_u32(block);
        state.s3[n*2] = block_lo;
        state.s3[n*2+1] = block_hi;
    }

    Ok(())
}

// ref) https://github.com/php/php-src/blob/00aa03bf8e92fc6675da507a1987c077650271d8/ext/standard/crypt_blowfish.c#L412-L442
pub fn encode(message: &[u8]) -> Vec<u8> {
    let mut res = vec![];

    // AAAAAABB BBBBCCCC CCDDDDDD
    for i in (0..message.len()).step_by(3) {
        // (AAAAAA?? >> 2) => AAAAAA
        let a = message[i] >> 2;
        res.push(consts::alphabet[a as usize]);

        let mut b = (message[i] & 0x03) << 4; // (BB << 4) => BB0000
        if i + 1 >= message.len() {
            res.push(consts::alphabet[b as usize]);
            return res;
        }
        b |= message[i+1] >> 4; // BB0000 | (BBBB???? >> 4) = BBBBBB
        res.push(consts::alphabet[b as usize]);

        let mut c = (message[i+1] & 0xf) << 2; // CCCC << 2 => CCCC00
        if i + 2 >= message.len() {
            res.push(consts::alphabet[c as usize]); // CCCC00
            return res;
        }
        c |= message[i+2] >> 6; // CCCC | (CC??????) >> 6 => CCCCCC
        res.push(consts::alphabet[c as usize]);

        let d = message[i+2] & 0x3f; // ??DDDDDD
        res.push(consts::alphabet[d as usize]);
    }
    res
}


#[test]
fn test_get_next_u32() {
    let test_cases = [
        (vec![1u8,2u8,3u8,4u8], 0usize, Some(0x01020304u32)),
        (vec![0u8], 0usize, Some(0u32)),
        (vec![], 0usize, None),
        (vec![0u8], 1usize, None),
    ];

    for test_case in test_cases.iter() { 
        let (byte_array, mut pos, expect) = test_case;
        let res = get_next_u32(byte_array, &mut pos);
        assert_eq!(res, *expect)
    }
}


#[test]
fn test_get_next_u32_continuous() {
    let byte_array = [0x00, 0x00, 0x00, 0x00, 0x00];
    let mut j: usize = 0;
    let res = get_next_u32(&byte_array, &mut j);
    assert_eq!(res, Some(0));
    assert_eq!(j, 4);
    let res = get_next_u32(&byte_array, &mut j);
    assert_eq!(res, Some(0));
    assert_eq!(j, 3);
}

#[test]
fn test_encocde() {
    let test_cases = [
        ("hello".as_bytes(), vec![89u8, 69u8, 84u8, 113u8, 90u8, 69u8, 54u8]),
        ("kurenaif".as_bytes(), vec![89u8, 49u8, 84u8, 119u8, 88u8, 85u8, 51u8, 102u8, 89u8, 85u8, 87u8]),
        ("a".as_bytes(), vec![87, 79]),
        ("".as_bytes(), vec![]),
    ];

    for test_case in test_cases.iter() { 
        let (src, expect) = test_case;
        let res = encode(src);
        assert_eq!(res, *expect);
    }
}