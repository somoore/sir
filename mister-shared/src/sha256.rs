// ---------------------------------------------------------------------------
// SHA-256 (std only, no external crates)
// ---------------------------------------------------------------------------

/// Pure Rust SHA-256 implementation. No unsafe, no external deps.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    // Pre-processing: pad message
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    result
}

/// Hex-encode a byte slice.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// SHA-256 hash and return as hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hello() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    // -----------------------------------------------------------------------
    // SHA-256 NIST CAVS short-message vectors
    // -----------------------------------------------------------------------

    /// Decode a hex string into bytes. Inline helper for tests only — keeps
    /// mister-shared zero-dependency.
    fn hex_decode(hex: &str) -> Vec<u8> {
        assert!(hex.len() % 2 == 0, "hex string must have even length");
        let bytes = hex.as_bytes();
        let mut out = Vec::with_capacity(hex.len() / 2);
        for i in (0..bytes.len()).step_by(2) {
            let hi = hex_nibble(bytes[i]);
            let lo = hex_nibble(bytes[i + 1]);
            out.push((hi << 4) | lo);
        }
        out
    }

    fn hex_nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("invalid hex nibble: {}", b as char),
        }
    }

    #[test]
    fn test_sha256_nist_vectors() {
        // (input_hex, expected_hex). Empty input is "" (zero-length).
        let cases: &[(&str, &str)] = &[
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("61", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
            ("616263", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                "6d65737361676520646967657374",
                "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
            ),
            (
                "6162636465666768696a6b6c6d6e6f707172737475767778797a",
                "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
            ),
            (
                "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839",
                "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
            ),
        ];
        for (input_hex, expected) in cases {
            let input = hex_decode(input_hex);
            let got = sha256_hex(&input);
            assert_eq!(
                &got, expected,
                "sha256 mismatch for input hex {:?}",
                input_hex
            );
        }

        // 56 'a' — 56*8 = 448 bits, exactly hits the padding boundary
        // (one block: payload fills bytes 0..55, 0x80 at 56, length at 56..64).
        let a56 = vec![b'a'; 56];
        assert_eq!(
            sha256_hex(&a56),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );

        // 64 'a' — exactly one block of input forces a second padding block.
        let a64 = vec![b'a'; 64];
        assert_eq!(
            sha256_hex(&a64),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );

        // 128 'a' — exactly two blocks of input.
        let a128 = vec![b'a'; 128];
        assert_eq!(
            sha256_hex(&a128),
            "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e"
        );

        // 1,000,000 'a' — the classic NIST long-message vector. Exercises many
        // block iterations and the bit-length encoding (8,000,000 bits).
        let a1m = vec![b'a'; 1_000_000];
        assert_eq!(
            sha256_hex(&a1m),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn test_sha256_block_boundaries() {
        // Stress the padding logic at every length where SHA-256 padding decisions
        // change: 0 (empty), 55 (last len that fits 1-block padding), 56 (forces
        // second padding block), 63 (one byte short of full block), 64 (full
        // block), 65 (one over), 119/120 (two-block boundary), 127/128 (two-block
        // / three-block boundary).
        let lengths = [0usize, 55, 56, 63, 64, 65, 119, 120, 127, 128];
        let mut hashes: Vec<String> = Vec::with_capacity(lengths.len());
        for &n in &lengths {
            let input = vec![0xabu8; n];
            let h1 = sha256_hex(&input);
            let h2 = sha256_hex(&input);
            assert_eq!(h1, h2, "sha256 not deterministic for len {}", n);
            hashes.push(h1);
        }
        // All ten hashes must be distinct.
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "sha256 collision between len {} and len {}",
                    lengths[i], lengths[j]
                );
            }
        }
    }
}
