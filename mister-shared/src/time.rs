// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

/// Return current time as Unix epoch seconds using std::time.
pub fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Return current time as Unix epoch millis.
pub fn now_epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_epoch() {
        let ts = now_epoch_secs();
        // Should be past 2024
        assert!(ts > 1_700_000_000);
    }
}
