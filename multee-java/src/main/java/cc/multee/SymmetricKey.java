package cc.multee;

import io.vavr.Tuple2;
import io.vavr.Tuple3;
import io.vavr.control.Either;

public interface SymmetricKey extends Key {

    /**
     * Performs encryption of plaintext using Galois/Counter mode of underlying block cipher.
     * Recommended  everywhere, unless compatibility or deterministic encryption (for indexing, etc) is needed
     * @param plainText - message to be encrypted
     * @param aad - associated data
     * @return Tuple of (ciphertext, IV, Tag)
     * Non "Right" Either may indicate violation of key usage limitations.
     */
    public Either<MulTeeError,Tuple3<byte[], IV, Tag>> seal(byte[] plainText, AssociatedData aad);
    /**
     * Performs encryption of plaintext using Galois/Counter mode of underlying block cipher.
     * Recommended  everywhere, unless compatibility or deterministic encryption (for indexing, etc) is needed
     * @param plainText - message to be encrypted
     * @return Tuple of (ciphertext, IV, Tag)
     * Non "Right" Either may indicate violation of key usage limitations.
     */
    public Either<MulTeeError,Tuple3<byte[], IV, Tag>> seal(byte[] plainText);

    /**
     * Decrypts and authenticates ciphertext in Galois/Counter mode of underlying block cipher.
     * @param cipherText - message to be encrypted
     * @param iv - initialization vector
     * @param tag - authentication tag
     * @param aad - associated data
     * @return plaintext
     * Non "Right" Either may indicate failure of tag verification as well as violation of key usage limitations.
     */
    public Either<MulTeeError,byte[]> unseal(byte[] cipherText, IV iv, Tag tag, AssociatedData aad);
    /**
     * Decrypts and authenticates ciphertext in Galois/Counter mode of underlying block cipher.
     * @param cipherText - message to be decrypted
     * @param iv - initialization vector
     * @param tag - authentication tag
     * @return plaintext
     * Non "Right" Either may indicate failure of tag verification as well as violation of key usage limitations.
     */
    public Either<MulTeeError,byte[]> unseal(byte[] cipherText, IV iv, Tag tag);

    /**
     * Performs encryption of plaintext using Cipher Block Chaining mode of underlying block cipher.
     * Recommended  to use only for compatibility or deterministic encryption
     * @param plainText - message to be encrypted
     * @param iv - initialization vector
     * @return Tuple of (ciphertext, IV)
     * Non "Right" Either may indicate violation of key usage limitations.
     */
//    @Deprecated
    public Either<MulTeeError,Tuple2<byte[],IV>> encryptCBC(byte[] plainText, IV iv );
    /**
     * Performs encryption of plaintext using Cipher Block Chaining mode of underlying block cipher.
     * Recommended  to use only for compatibility or deterministic encryption
     * @param plainText - message to be encrypted
     * @return Tuple of (ciphertext, IV)
     * Non "Right" Either may indicate violation of key usage limitations.
     */
//    @Deprecated
    public Either<MulTeeError,Tuple2<byte[],IV>> encryptCBC(byte[] plainText );

    /**
     * Decrypts ciphertext in Cipher Block Chaining mode of underlying block cipher.
     * @param cipherText - message to be encrypted
     * @param iv - initialization vector
     * @return plaintext
     * Non "Right" Either may indicate padding error as well as violation of key usage limitations.
     */
    public Either<MulTeeError,byte[]> decryptCBC(byte[] cipherText, IV iv);
}
