package com.chpark.crypto;

/**
 * Thrown when a cryptographic operation fails — typically a GCM authentication
 * tag mismatch caused by a wrong password or tampered ciphertext.
 */
public class CryptoException extends Exception {

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
