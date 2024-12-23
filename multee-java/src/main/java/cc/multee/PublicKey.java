package cc.multee;

import io.vavr.control.Either;

public interface PublicKey {
    /**
     * Verifies signature of the provided message using underlying asymmetric (EC/RSA) key.
     * @param message - message to be encrypted
     * @param signature - message to be encrypted
     * @return verification resilt
     * Non "Right" Either indicates failure of signature verification
     */
    public Either<MulTeeError,Boolean> verify(byte[] message, Signature signature );
}
