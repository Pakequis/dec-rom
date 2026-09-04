//! Compression-ratio based fitness scoring: candidates that decode to genuine code/data
//! compress better than incorrect bit-permutations, since only the correct bit mapping
//! preserves local byte-level redundancy (repeated sequences, structured tables).

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

/// Higher is better. `0.0` for empty input. A ratio of e.g. `0.6` means the
/// compressed form is 40% of the original size.
///
/// Uses zlib's fastest compression level, not its best: this function is
/// `autofix::find_scrambling`'s fitness heuristic, called on every candidate
/// the search evaluates — tens of thousands of times per run, including
/// full-file recompressions in Phase 3's hot loop (`greedy_polish`,
/// `simulated_anneal`) — so it's on the search's critical path under a hard
/// wall-clock time budget. Only the *relative order* between candidates'
/// scores matters here, never the absolute compressed size (nothing
/// compressed by this function is ever written to disk), and a faster
/// compression level preserves that relative ordering closely enough for
/// ranking while letting the fixed time budget cover several times more
/// candidates/restarts.
pub fn compression_score(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut encoder = ZlibEncoder::new(Vec::with_capacity(data.len() / 2), Compression::fast());
    encoder.write_all(data).expect("writing to an in-memory Vec cannot fail");
    let compressed = encoder.finish().expect("finishing an in-memory zlib stream cannot fail");
    1.0 - (compressed.len() as f64 / data.len() as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repetitive_data_scores_higher_than_random_noise() {
        let repetitive: Vec<u8> = (0..4096u32).map(|i| (i % 8) as u8).collect();
        // A fixed pseudo-random sequence, not actual randomness (which
        // would make this test flaky) — a simple LCG produces byte-value
        // noise with no repeating structure for a compressor to exploit.
        let mut seed: u64 = 12345;
        let noise: Vec<u8> = (0..4096u32)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                (seed >> 56) as u8
            })
            .collect();

        let repetitive_score = compression_score(&repetitive);
        let noise_score = compression_score(&noise);
        assert!(
            repetitive_score > noise_score,
            "repetitive={repetitive_score} noise={noise_score}"
        );
    }

    #[test]
    fn empty_input_scores_zero() {
        assert_eq!(compression_score(&[]), 0.0);
    }
}
