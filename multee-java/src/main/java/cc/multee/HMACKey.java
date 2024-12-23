package cc.multee;

import io.vavr.control.Either;

public interface HMACKey extends Key {

    /**
     * Computes Hash MAC message authentication code of the message
     * @param message
     * @return HMAC(SHA-256) of the message
     */
    Either<MulTeeError,MAC> hmacSHA256(byte[] message);
}
