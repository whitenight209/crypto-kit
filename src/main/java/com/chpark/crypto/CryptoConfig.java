package com.chpark.crypto;

/**
 * Immutable configuration for CryptoEngine.
 * All lengths are in bytes unless noted (tagLength is in bits).
 */
public record CryptoConfig(
        int saltLength,
        int nonceLength,
        int keyLength,
        int tagLength,
        int iterationCount
) {
    public static final CryptoConfig DEFAULT = new CryptoConfig(16, 12, 256, 128, 310_000);

    public CryptoConfig {
        if (saltLength <= 0) throw new IllegalArgumentException("saltLength must be > 0");
        if (nonceLength <= 0) throw new IllegalArgumentException("nonceLength must be > 0");
        if (keyLength != 128 && keyLength != 192 && keyLength != 256)
            throw new IllegalArgumentException("keyLength must be 128, 192, or 256");
        if (tagLength != 128) throw new IllegalArgumentException("tagLength must be 128");
        if (iterationCount < 1) throw new IllegalArgumentException("iterationCount must be >= 1");
    }
}
