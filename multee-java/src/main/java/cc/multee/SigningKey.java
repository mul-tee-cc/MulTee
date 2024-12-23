package cc.multee;

import io.vavr.control.Either;

public interface SigningKey extends AsymmetricKey {

    /**
     * Signs the provided message using underlying asymmetric (EC/RSA) key.
     * In case of RSA, PSS padding is used in combination wih SHA-256 digest.
     * @param message - message to be encrypted
     * @return signature
     * Non "Right" Either may indicate violation of key usage limitations.
     */
    public Either<MulTeeError,Signature> sign(byte[] message );

}
