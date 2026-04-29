package com.chpark.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class CryptoEngineTest {

    private CryptoEngine engine;

    @BeforeEach
    void setUp() {
        engine = new CryptoEngine();
    }

    // -------------------------------------------------------------------------
    // 9.1  Fast-path round-trip
    // -------------------------------------------------------------------------
    @Test
    void fastPath_roundTrip_returnsOriginalPlaintext() throws Exception {
        byte[] key = engine.deriveKey("test-password", new byte[16]);
        byte[] plaintext = "Hello, ebook!".getBytes();

        byte[] ciphertext = engine.encrypt(key, plaintext);
        byte[] recovered = engine.decrypt(key, ciphertext);

        assertArrayEquals(plaintext, recovered);
    }

    // -------------------------------------------------------------------------
    // 9.2  Convenience-path round-trip
    // -------------------------------------------------------------------------
    @Test
    void conveniencePath_roundTrip_returnsOriginalPlaintext() throws Exception {
        byte[] plaintext = "Ebook chapter content".getBytes();
        String password = "s3cur3P@ss";

        byte[] ciphertext = engine.encrypt(password, plaintext);
        byte[] recovered = engine.decrypt(password, ciphertext);

        assertArrayEquals(plaintext, recovered);
    }

    // -------------------------------------------------------------------------
    // 9.3  Fast-path output length
    // -------------------------------------------------------------------------
    @Test
    void fastPath_outputLength_isNoncePlusCiphertextPlusTag() throws Exception {
        byte[] key = engine.deriveKey("key-pass", new byte[16]);
        byte[] plaintext = "length test".getBytes();

        byte[] ciphertext = engine.encrypt(key, plaintext);

        int expected = 12 + plaintext.length + 16; // nonce + plaintext + tag
        assertEquals(expected, ciphertext.length);
    }

    // -------------------------------------------------------------------------
    // 9.4  Convenience-path output length
    // -------------------------------------------------------------------------
    @Test
    void conveniencePath_outputLength_isSaltNonceCiphertextTag() throws Exception {
        byte[] plaintext = "length test conv".getBytes();

        byte[] ciphertext = engine.encrypt("password", plaintext);

        int expected = 16 + 12 + plaintext.length + 16; // salt + nonce + plaintext + tag
        assertEquals(expected, ciphertext.length);
    }

    // -------------------------------------------------------------------------
    // 9.5  Convenience-path uniqueness (unique salt/nonce per call)
    // -------------------------------------------------------------------------
    @Test
    void conveniencePath_twoCallsSamePlaintext_produceDifferentCiphertext() throws Exception {
        byte[] plaintext = "same content".getBytes();
        String password = "same-password";

        byte[] c1 = engine.encrypt(password, plaintext);
        byte[] c2 = engine.encrypt(password, plaintext);

        assertFalse(Arrays.equals(c1, c2), "Each encryption must produce unique ciphertext");
    }

    // -------------------------------------------------------------------------
    // 9.6  Wrong password throws CryptoException
    // -------------------------------------------------------------------------
    @Test
    void conveniencePath_wrongPassword_throwsCryptoException() throws Exception {
        byte[] ciphertext = engine.encrypt("correct-password", "secret".getBytes());

        assertThrows(CryptoException.class,
                () -> engine.decrypt("wrong-password", ciphertext));
    }

    // -------------------------------------------------------------------------
    // 9.7  Tampered ciphertext throws CryptoException (both paths)
    // -------------------------------------------------------------------------
    @Test
    void fastPath_tamperedCiphertext_throwsCryptoException() throws Exception {
        byte[] key = engine.deriveKey("tamper-key", new byte[16]);
        byte[] ciphertext = engine.encrypt(key, "tamper test".getBytes());

        ciphertext[ciphertext.length - 2] ^= 0xFF; // flip a byte in the auth tag area
        assertThrows(CryptoException.class, () -> engine.decrypt(key, ciphertext));
    }

    @Test
    void conveniencePath_tamperedCiphertext_throwsCryptoException() throws Exception {
        byte[] ciphertext = engine.encrypt("password", "tamper test".getBytes());

        ciphertext[ciphertext.length - 2] ^= 0xFF;
        assertThrows(CryptoException.class, () -> engine.decrypt("password", ciphertext));
    }

    // -------------------------------------------------------------------------
    // 9.8  Truncated ciphertext throws IllegalArgumentException (both paths)
    // -------------------------------------------------------------------------
    @Test
    void fastPath_truncatedCiphertext_throwsIllegalArgumentException() throws Exception {
        byte[] key = engine.deriveKey("trunc-key", new byte[16]);
        byte[] tooShort = new byte[28]; // need >= 29 (nonce 12 + tag 16 + 1)

        assertThrows(IllegalArgumentException.class, () -> engine.decrypt(key, tooShort));
    }

    @Test
    void conveniencePath_truncatedCiphertext_throwsIllegalArgumentException() {
        byte[] tooShort = new byte[44]; // need >= 45 (salt 16 + nonce 12 + tag 16 + 1)

        assertThrows(IllegalArgumentException.class,
                () -> engine.decrypt("password", tooShort));
    }

    // -------------------------------------------------------------------------
    // 9.9  Null inputs throw IllegalArgumentException
    // -------------------------------------------------------------------------
    @Test
    void encryptFastPath_nullInputs_throwIllegalArgumentException() {
        byte[] key = new byte[32];
        assertThrows(IllegalArgumentException.class, () -> engine.encrypt((byte[]) null, new byte[1]));
        assertThrows(IllegalArgumentException.class, () -> engine.encrypt(key, (byte[]) null));
    }

    @Test
    void encryptConveniencePath_nullInputs_throwIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> engine.encrypt((String) null, new byte[1]));
        assertThrows(IllegalArgumentException.class, () -> engine.encrypt("password", (byte[]) null));
    }

    @Test
    void decryptFastPath_nullInputs_throwIllegalArgumentException() {
        byte[] key = new byte[32];
        assertThrows(IllegalArgumentException.class, () -> engine.decrypt((byte[]) null, new byte[30]));
        assertThrows(IllegalArgumentException.class, () -> engine.decrypt(key, (byte[]) null));
    }

    @Test
    void decryptConveniencePath_nullInputs_throwIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> engine.decrypt((String) null, new byte[50]));
        assertThrows(IllegalArgumentException.class, () -> engine.decrypt("password", (byte[]) null));
    }

    @Test
    void deriveKey_nullInputs_throwIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> engine.deriveKey(null, new byte[16]));
        assertThrows(IllegalArgumentException.class, () -> engine.deriveKey("password", null));
    }

    // -------------------------------------------------------------------------
    // 9.10  deriveKey is deterministic
    // -------------------------------------------------------------------------
    @Test
    void deriveKey_sameInputs_returnsSameKey() throws Exception {
        byte[] salt = new byte[16];
        byte[] k1 = engine.deriveKey("deterministic", salt);
        byte[] k2 = engine.deriveKey("deterministic", salt);

        assertArrayEquals(k1, k2);
    }

    // -------------------------------------------------------------------------
    // 9.11  Default CryptoConfig values
    // -------------------------------------------------------------------------
    @Test
    void defaultCryptoConfig_valuesAreCorrect() {
        CryptoConfig cfg = CryptoConfig.DEFAULT;
        assertEquals(16, cfg.saltLength());
        assertEquals(12, cfg.nonceLength());
        assertEquals(256, cfg.keyLength());
        assertEquals(128, cfg.tagLength());
        assertEquals(310_000, cfg.iterationCount());
    }
}
