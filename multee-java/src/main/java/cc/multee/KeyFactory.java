package cc.multee;

import io.vavr.control.Either;

public interface KeyFactory {


    /**
     * Returns handle of the key. If keyName can be resolved as "global" key name, reference to corresponding key is returned.
     * Otherwise, reference to key local to the connected KMS is returned.
     * For keys with setup key rotation, for decryption, desired key version can be specified by appending #\<revision\> to keyName
     * @param keyName - name of desired key, with or without key revision
     * @return reference to the key
     * Non "Right" Either may indicate
     * * absent key
     * * lack of permissions to use the key
     * * configuration error
     */
    Either<MulTeeError,KeyHandle> getKey(String keyName );
}
