use sha2::{Digest, Sha256};

pub fn flat_skin() -> Vec<u8> {
    let mut skin = vec![0u8; 64 * 32 * 4];
    for y in 0..32 {
        for x in 0..64 {
            let color = [96, 128, 160, 255];
            let idx = (y * 64 + x) * 4;
            skin[idx..idx + 4].copy_from_slice(&color);
        }
    }
    skin
}

pub fn player_like_skin(seed: &str) -> Vec<u8> {
    let digest = Sha256::digest(seed.as_bytes());
    let hair = [
        45 + digest[0] % 45,
        28 + digest[1] % 35,
        18 + digest[2] % 25,
        255,
    ];
    let skin_tone = [
        164 + digest[3] % 45,
        112 + digest[4] % 45,
        74 + digest[5] % 35,
        255,
    ];
    let shirt = [
        35 + digest[6] % 80,
        80 + digest[7] % 110,
        110 + digest[8] % 100,
        255,
    ];
    let pants = [
        35 + digest[9] % 45,
        45 + digest[10] % 55,
        85 + digest[11] % 90,
        255,
    ];
    let shoe = [28, 26, 25, 255];
    let mut skin = vec![0u8; 64 * 32 * 4];
    for y in 0..32 {
        for x in 0..64 {
            let mut color = if y < 8 {
                if (1..=6).contains(&(x % 8)) && (2..=6).contains(&y) {
                    skin_tone
                } else {
                    hair
                }
            } else if y < 20 {
                if (x / 8) % 4 == 1 {
                    skin_tone
                } else {
                    shirt
                }
            } else if y < 29 {
                pants
            } else {
                shoe
            };
            let noise = (((x * 13 + y * 17) as u8) ^ digest[(x + y) % digest.len()]) & 0x0f;
            let delta = noise as i16 - 7;
            shade_rgba(&mut color, delta);
            let idx = (y * 64 + x) * 4;
            skin[idx..idx + 4].copy_from_slice(&color);
        }
    }
    skin
}

fn shade_rgba(color: &mut [u8; 4], delta: i16) {
    for channel in &mut color[..3] {
        let value = *channel as i16 + delta;
        *channel = value.clamp(0, 255) as u8;
    }
}