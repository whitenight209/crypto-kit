package com.chpark.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * High-performance AES-256-GCM encryption engine backed by BouncyCastle.
 *
 * <p>Two API tiers:
 * <ul>
 *   <li><b>Convenience path</b> – {@code encrypt(String password, byte[] plaintext)} /
 *       {@code decrypt(String password, byte[] ciphertext)}: derives a key via PBKDF2 inline.
 *   <li><b>Fast path</b> – {@code encrypt(byte[] key, byte[] plaintext)} /
 *       {@code decrypt(byte[] key, byte[] ciphertext)}: caller supplies a pre-derived 32-byte key;
 *       zero PBKDF2 overhead, suitable for batch encryption.
 * </ul>
 *
 * <p>Wire formats:
 * <ul>
 *   <li>Convenience path: {@code [magic header (5)][salt (16)][nonce (12)][ciphertext + auth tag (16)]}
 *   <li>Fast path: {@code [magic header (5)][nonce (12)][ciphertext + auth tag (16)]}
 * </ul>
 *
 * <p>Use {@link #deriveKey(String, byte[])} to derive a key once and reuse it across
 * many fast-path calls to amortise the PBKDF2 cost.
 */
public class CryptoEngine {

    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final byte[] MAGIC_HEADER = new byte[] {'C', 'K', 'I', 'T', 1};

    private final CryptoConfig config;
    private final SecureRandom random = new SecureRandom();

    /** One Cipher instance per thread — re-initialised before every use. */
    private static final ThreadLocal<Cipher> CIPHER_LOCAL =
            ThreadLocal.withInitial(CryptoEngine::createCipher);

    public CryptoEngine() {
        this(CryptoConfig.DEFAULT);
    }

    public CryptoEngine(CryptoConfig config) {
        if (config == null) throw new IllegalArgumentException("config must not be null");
        this.config = config;
    }

    // -------------------------------------------------------------------------
    // Key derivation
    // -------------------------------------------------------------------------

    /**
     * Derives a 256-bit AES key from {@code password} and {@code salt} using
     * PBKDF2WithHmacSHA256 with the configured iteration count.
     *
     * <p>The returned key can be cached and reused with the fast-path overloads
     * to avoid repeated PBKDF2 overhead.
     */
    public byte[] deriveKey(String password, byte[] salt)
            throws CryptoException {
        if (password == null) throw new IllegalArgumentException("password must not be null");
        if (salt == null) throw new IllegalArgumentException("salt must not be null");
        try {
            PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(),
                    salt,
                    config.iterationCount(),
                    config.keyLength()
            );
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            byte[] key = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return key;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException("Key derivation failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // Fast-path encryption  (pre-keyed, no PBKDF2)
    // wire format: [magic header (5)][nonce (12)][ciphertext + auth tag (16)]
    // -------------------------------------------------------------------------

    /**
     * Encrypts {@code plaintext} with AES-256-GCM using the supplied 32-byte {@code key}.
     *
     * <p>No key derivation is performed; the caller is responsible for supplying a
     * cryptographically strong key (e.g., via {@link #deriveKey}).
     *
     * @return {@code [magic header (5 bytes)][nonce (12 bytes)][ciphertext + GCM auth tag (16 bytes)]}
     */
    public byte[] encrypt(byte[] key, byte[] plaintext) throws CryptoException {
        if (key == null) throw new IllegalArgumentException("key must not be null");
        if (plaintext == null) throw new IllegalArgumentException("plaintext must not be null");
        if (key.length != config.keyLength() / 8)
            throw new IllegalArgumentException("key must be " + (config.keyLength() / 8) + " bytes");

        byte[] nonce = generateRandom(config.nonceLength());
        byte[] ciphertextAndTag = gcmEncrypt(key, nonce, plaintext);

        return buildFastPathOutput(nonce, ciphertextAndTag);
    }

    // -------------------------------------------------------------------------
    // Convenience-path encryption  (password-based, derives key inline)
    // wire format: [magic header (5)][salt (16)][nonce (12)][ciphertext + auth tag (16)]
    // -------------------------------------------------------------------------

    /**
     * Encrypts {@code plaintext} with AES-256-GCM.
     *
     * <p>A random salt is generated, the AES key is derived via PBKDF2, and the
     * salt is prepended to the output blob so that decryption needs only the password.
     *
     * @return {@code [magic header (5 bytes)][salt (16 bytes)][nonce (12 bytes)][ciphertext + GCM auth tag (16 bytes)]}
     */
    public byte[] encrypt(String password, byte[] plaintext) throws CryptoException {
        if (password == null) throw new IllegalArgumentException("password must not be null");
        if (plaintext == null) throw new IllegalArgumentException("plaintext must not be null");

        byte[] salt = generateRandom(config.saltLength());
        byte[] key = deriveKey(password, salt);
        try {
            byte[] nonce = generateRandom(config.nonceLength());
            byte[] ciphertextAndTag = gcmEncrypt(key, nonce, plaintext);

            byte[] output = new byte[MAGIC_HEADER.length + salt.length + nonce.length + ciphertextAndTag.length];
            System.arraycopy(MAGIC_HEADER, 0, output, 0, MAGIC_HEADER.length);
            System.arraycopy(salt, 0, output, MAGIC_HEADER.length, salt.length);
            System.arraycopy(nonce, 0, output, MAGIC_HEADER.length + salt.length, nonce.length);
            System.arraycopy(ciphertextAndTag, 0, output, MAGIC_HEADER.length + salt.length + nonce.length,
                    ciphertextAndTag.length);
            return output;
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    // -------------------------------------------------------------------------
    // Fast-path decryption  (pre-keyed, no PBKDF2)
    // expects: [magic header (5)][nonce (12)][ciphertext + auth tag (16)]
    // -------------------------------------------------------------------------

    /**
     * Decrypts a blob produced by {@link #encrypt(byte[], byte[])}.
     *
     * <p>Headerless blobs produced by older crypto-kit versions are still accepted.
     *
     * @throws CryptoException         if the GCM authentication tag does not verify
     * @throws IllegalArgumentException if {@code ciphertext} is too short or inputs are null
     */
    public byte[] decrypt(byte[] key, byte[] ciphertext) throws CryptoException {
        if (key == null) throw new IllegalArgumentException("key must not be null");
        if (ciphertext == null) throw new IllegalArgumentException("ciphertext must not be null");
        if (key.length != config.keyLength() / 8)
            throw new IllegalArgumentException("key must be " + (config.keyLength() / 8) + " bytes");

        boolean hasHeader = hasMagicHeader(ciphertext);
        int minLen = config.nonceLength() + config.tagLength() / 8 + 1;
        if (hasHeader) minLen += MAGIC_HEADER.length;
        if (ciphertext.length < minLen)
            throw new IllegalArgumentException(
                    "ciphertext too short: need at least " + minLen + " bytes");

        int nonceStart = hasHeader ? MAGIC_HEADER.length : 0;
        byte[] nonce = Arrays.copyOfRange(ciphertext, nonceStart, nonceStart + config.nonceLength());
        byte[] body = Arrays.copyOfRange(ciphertext, nonceStart + config.nonceLength(), ciphertext.length);
        return gcmDecrypt(key, nonce, body);
    }

    // -------------------------------------------------------------------------
    // Convenience-path decryption  (password-based, derives key inline)
    // expects: [magic header (5)][salt (16)][nonce (12)][ciphertext + auth tag (16)]
    // -------------------------------------------------------------------------

    /**
     * Decrypts a blob produced by {@link #encrypt(String, byte[])}.
     *
     * <p>Headerless blobs produced by older crypto-kit versions are still accepted.
     *
     * @throws CryptoException         if the GCM authentication tag does not verify
     *                                  (wrong password or tampered ciphertext)
     * @throws IllegalArgumentException if {@code ciphertext} is too short or inputs are null
     */
    public byte[] decrypt(String password, byte[] ciphertext) throws CryptoException {
        if (password == null) throw new IllegalArgumentException("password must not be null");
        if (ciphertext == null) throw new IllegalArgumentException("ciphertext must not be null");

        boolean hasHeader = hasMagicHeader(ciphertext);
        int minLen = config.saltLength() + config.nonceLength() + config.tagLength() / 8 + 1;
        if (hasHeader) minLen += MAGIC_HEADER.length;
        if (ciphertext.length < minLen)
            throw new IllegalArgumentException(
                    "ciphertext too short: need at least " + minLen + " bytes");

        int saltStart = hasHeader ? MAGIC_HEADER.length : 0;
        byte[] salt = Arrays.copyOfRange(ciphertext, saltStart, saltStart + config.saltLength());
        int nonceStart = saltStart + config.saltLength();
        byte[] nonce = Arrays.copyOfRange(ciphertext, nonceStart, nonceStart + config.nonceLength());
        byte[] body = Arrays.copyOfRange(ciphertext, nonceStart + config.nonceLength(), ciphertext.length);

        byte[] key = deriveKey(password, salt);
        try {
            return gcmDecrypt(key, nonce, body);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * Returns true when {@code data} starts with the crypto-kit encrypted-data header.
     */
    public static boolean hasMagicHeader(byte[] data) {
        if (data == null || data.length < MAGIC_HEADER.length) return false;
        for (int i = 0; i < MAGIC_HEADER.length; i++) {
            if (data[i] != MAGIC_HEADER[i]) return false;
        }
        return true;
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private byte[] gcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext) throws CryptoException {
        try {
            Cipher cipher = CIPHER_LOCAL.get();
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(config.tagLength(), nonce));
            return cipher.doFinal(plaintext);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Encryption failed: invalid AES key or GCM parameters", e);
        } catch (Exception e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    private byte[] gcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertextAndTag)
            throws CryptoException {
        try {
            Cipher cipher = CIPHER_LOCAL.get();
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(config.tagLength(), nonce));
            return cipher.doFinal(ciphertextAndTag);
        } catch (AEADBadTagException e) {
            throw new CryptoException("Decryption failed: authentication tag mismatch", e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Decryption failed: invalid AES key or GCM parameters", e);
        } catch (Exception e) {
            throw new CryptoException("Decryption failed", e);
        }
    }

    private byte[] generateRandom(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    private static byte[] buildFastPathOutput(byte[] nonce, byte[] ciphertextAndTag) {
        byte[] output = new byte[MAGIC_HEADER.length + nonce.length + ciphertextAndTag.length];
        System.arraycopy(MAGIC_HEADER, 0, output, 0, MAGIC_HEADER.length);
        System.arraycopy(nonce, 0, output, MAGIC_HEADER.length, nonce.length);
        System.arraycopy(ciphertextAndTag, 0, output, MAGIC_HEADER.length + nonce.length,
                ciphertextAndTag.length);
        return output;
    }

    private static Cipher createCipher() {
        try {
            return Cipher.getInstance(AES_GCM_ALGORITHM);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("AES/GCM/NoPadding is not available", e);
        }
    }
}
