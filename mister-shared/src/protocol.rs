// ---------------------------------------------------------------------------
// MSTR/1 Protocol
// ---------------------------------------------------------------------------

use std::io::{self, Read, Write};

/// Magic bytes for MSTR/1 wire format.
pub const PROTOCOL_MAGIC: &[u8; 4] = b"MSTR";
/// Protocol version.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Encode a payload into MSTR/1 wire format: magic(4) + version(1) + len(4 BE) + payload.
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(9 + payload.len());
    buf.extend_from_slice(PROTOCOL_MAGIC);
    buf.push(PROTOCOL_VERSION);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decode a MSTR/1 frame from a reader. Returns the payload bytes.
pub fn decode_frame<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 9];
    reader.read_exact(&mut header)?;

    if &header[0..4] != PROTOCOL_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid MSTR/1 magic",
        ));
    }
    if header[4] != PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported MSTR/1 version: {}", header[4]),
        ));
    }

    let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
    const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024; // 10 MB
    if len as usize > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {} bytes (max {})", len, MAX_FRAME_BYTES),
        ));
    }
    let len = len as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

/// Write an MSTR/1 frame to a writer.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let frame = encode_frame(payload);
    writer.write_all(&frame)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_protocol_encode_decode() {
        let payload = b"hello world";
        let frame = encode_frame(payload);
        assert_eq!(&frame[0..4], b"MSTR");
        assert_eq!(frame[4], 0x01);
        let len = u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]);
        assert_eq!(len, 11);

        let mut cursor = io::Cursor::new(&frame);
        let decoded = decode_frame(&mut cursor).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_protocol_empty_payload() {
        let frame = encode_frame(b"");
        let mut cursor = io::Cursor::new(&frame);
        let decoded = decode_frame(&mut cursor).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_protocol_bad_magic() {
        let mut frame = encode_frame(b"test");
        frame[0] = b'X';
        let mut cursor = io::Cursor::new(&frame);
        assert!(decode_frame(&mut cursor).is_err());
    }
}
