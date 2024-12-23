package cc.multee;

import io.vavr.control.Either;

public interface KeyHandle extends Key {

    /**
     * Returns key handle which can be used for symmetric crypto operations
     * @return reference to the HMAC key handle
     * Non "Right" Either may indicate
     * * key which can only be used for asymmetric or HMAC crypto purposes
     * * lack of permissions to use the key
     */
    Either<MulTeeError,SymmetricKey> symmetric();
    /**
     * Returns key handle which can be used for Hash-based Message Authentication Code crypto operations.
     * @return reference to the signing key handle
     * Non "Right" Either may indicate
     * * key which can only be used for asymmetric crypto purposes
     * * lack of permissions to use the key
     */
    Either<MulTeeError,HMACKey> hmac();
    /**
     * Returns key handle which can be used for signing operations
     * @return reference to the signing key handle
     * Non "Right" Either may indicate
     * * key which can only be used for symmetric crypto or encryption/authentication purposes
     * * lack of permissions to use the key
     */    Either<MulTeeError,SigningKey> signing();
    Either<MulTeeError, AsymmEncryptionKey> asymmEncryption();
}
