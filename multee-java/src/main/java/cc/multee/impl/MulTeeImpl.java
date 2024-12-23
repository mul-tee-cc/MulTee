package cc.multee.impl;

import cc.multee.*;
import io.vavr.control.Either;
import io.vavr.collection.Set;
import io.vavr.collection.HashSet;
import io.vavr.collection.Map;
import io.vavr.collection.HashMap;
import io.vavr.control.Option;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;

public class MulTeeImpl implements KeyFactory {

    private final Native jni;
    private final Map<String, Integer> keys;

    static MulTeeImpl dummyFactory() {
        return (MulTeeImpl) MulTeeException.unwrap(getKeyFactory("file://./.dummy", HashSet.empty(),"dummy"));
    }

    public static Either<MulTeeError,KeyFactory> getKeyFactory(String keyUriPrefix, Set<String> keyNames, String idCcredentials ) {
        String[] keyArray = keyNames.toJavaList().toArray(new String[0]);
        final Map<String, Integer> keys = HashMap.ofEntries(keyNames.zipWithIndex());

        return Native.make(keyUriPrefix,keyArray,idCcredentials)
                     .map( jni -> new MulTeeImpl(jni,keys) );
    }
    public static Either<MulTeeError,KeyFactory> getKeyFactory(String keyUriPrefix, Set<String> keyNames, InputStream credentialsZIP ) {
        try {
            return getKeyFactory(keyUriPrefix, keyNames, storeStream(credentialsZIP));
        } catch (IOException e) {
            return Either.left(MulTeeErrorImpl.of(Errors.CREDENTIALS_IO,e.getMessage()));
        }
    }

    private MulTeeImpl(final Native jni, final Map<String, Integer> keys ) {

        this.jni = jni;
        this.keys = keys;
    }

    private static String storeStream(InputStream credentialsZIP) throws IOException {
        String separator = System.getProperty("file.separator");
        File tmp = new File(System.getProperty("java.io.tmpdir"));
        Path tmpFile;

        File tc = new File(tmp, "multee");
        tc.mkdir();
        tmpFile = Files.createTempFile(tc.toPath(), "machine-","zip").toAbsolutePath();
        Files.copy(credentialsZIP, tmpFile, StandardCopyOption.REPLACE_EXISTING);
        return tmpFile.toString();
    }

    public Either<MulTeeError, KeyHandle> getKey(String name ) {
        return keys.get(name)
                .toEither(MulTeeErrorImpl.of(Errors.CRYPTO_INVALID_KEY_NAME,"Accessing undeclared key: "+name))
                .map( idx -> new MulTeeKeyImpl(jni,idx))
                .flatMap(this::temporaryExistenceCheck);
    }

    // TODO: actually check in Native.importKeys
    private Either<MulTeeError, MulTeeKeyImpl> temporaryExistenceCheck(MulTeeKeyImpl kh) {
        return kh.keyLoaded().map( _ignore -> kh);
    }

    Either<MulTeeError, Option.None<Void>> generateCSR(String csrZipFile, String SN) {
        Either<MulTeeError, Option.None<Void>> result = jni.generateCSR(csrZipFile,SN);
        if(result.isRight())
            System.out.println("CSR written to: " + csrZipFile);
        return result;
    }
}
