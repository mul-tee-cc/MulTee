package cc.multee.impl;

import cc.multee.*;
import io.vavr.Tuple;
import io.vavr.Tuple2;
import io.vavr.Tuple3;
import io.vavr.control.Either;

class MulTeeKeyImpl implements KeyHandle, SymmetricKey, SigningKey, HMACKey, AsymmEncryptionKey, PublicKey {

    private final Native jni;
    private final int keyIndex;

    MulTeeKeyImpl(Native jni, int keyIndex ) {
        this.jni = jni;
        this.keyIndex = keyIndex;
    }

    @Override
    public PublicKey getPublicKey() {
        return this;
    }

    @Override
    public String getName() {
        return jni.getName(keyIndex);
    }

    @Override
    public String getFullName() {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getLength() {
        return jni.keyLength(keyIndex);
    }

    Either<MulTeeError, Long> keyLoaded() {
        return jni.keyLen(keyIndex);
    }

    @Override
    public Algorithm getAlgorithm() {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    public Either<MulTeeError,SymmetricKey> symmetric() {
        return Either.right(this);
    }

    @Override
    public Either<MulTeeError,HMACKey> hmac() {
        return Either.right(this);
    }

    @Override
    public Either<MulTeeError, SigningKey> signing() {
        return Either.right(this);
    }

    @Override
    public Either<MulTeeError, AsymmEncryptionKey> asymmEncryption() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Either<MulTeeError,Signature> sign(byte[] message) {
        return jni.keySign(keyIndex, message);
    }

    @Override
    public Either<MulTeeError, Boolean> verify(byte[] message, Signature signature) {
        return jni.keyVerify(keyIndex, message, signature.getBytes());
    }

    @Override
    public Either<MulTeeError, Tuple3<byte[], IV, Tag>> seal(byte[] plainText, AssociatedData aad) {
        byte[] iv = new byte[(int)Const.MULTEE_GCM_IV_BYTES];
        byte[] tag = new byte[(int)Const.MULTEE_GCM_TAG_BYTES];

        return jni.keyCryptGcm(keyIndex, true, iv, aad.getBytes(), plainText, tag)
          .map( cipherText -> Tuple.of( cipherText, IV.of(iv), Tag.of(tag) ));
    }

    public Either<MulTeeError, Tuple3<byte[], IV, Tag>> seal(byte[] plainText) {
        return seal(plainText,AssociatedData.without());
    }

    @Override
    public Either<MulTeeError, byte[]> unseal(byte[] cipherText, IV iv, Tag tag, AssociatedData aad) {
        return jni.keyCryptGcm(keyIndex, false, iv.getBytes(), aad.getBytes(), cipherText, tag.getBytes());
    }

    public Either<MulTeeError, byte[]> unseal(byte[] cipherText, IV iv, Tag tag) {
        return unseal(cipherText,iv,tag,AssociatedData.without());
    }

    @Override
    public Either<MulTeeError,Tuple2<byte[],IV>> encryptCBC(byte[] plainText) {
        return jni.keyCryptCbc(keyIndex, true, false, IV.zero().getBytes(), plainText);
    }

    public Either<MulTeeError,Tuple2<byte[],IV>> encryptCBC(byte[] plainText, IV ivBytes) {
        return jni.keyCryptCbc(keyIndex, true, true, ivBytes.getBytes(), plainText);
    }

    @Override
    public Either<MulTeeError, byte[]> decryptCBC(byte[] cipherText, IV iv) {
        return jni.keyCryptCbc(keyIndex, false, true, iv.getBytes(), cipherText).map(Tuple2::_1);
    }

    @Override
    public Either<MulTeeError,MAC> hmacSHA256(byte[] data) {
        return jni.keyHmacSha256(keyIndex, data);
    }
}
