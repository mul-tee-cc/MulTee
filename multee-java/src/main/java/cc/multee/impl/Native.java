package cc.multee.impl;

import cc.multee.*;
import io.vavr.Tuple;
import io.vavr.Tuple2;
import io.vavr.control.Either;
import io.vavr.control.Option.None;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Map;
import java.util.logging.Logger;

class Native {

    private static final Logger nativeLogger = Logger.getLogger("multee.native");

    private final long enclaveRef;

    private static final Map<Integer,Errors> code2err = MulTeeErrorImpl.getCode2err();

    public static Either<MulTeeError,Native> make(String keyUriPrefix, String[] keyNames, String credentialsZIP) {
        return getNativeLibs()
                .flatMap( nativeLibraries -> init(keyUriPrefix,keyNames,credentialsZIP,nativeLibraries))
                .map(Native::new);
    }

    private static Either<MulTeeError,Long> init(String keyUriPrefix, String[] keyNames, String credentialsZIP, String[] nativeLibraries) {
        String separator = System.getProperty("file.separator");
        String tmpDir = null;

        File tmp = new File(System.getProperty("java.io.tmpdir"));
        File tc = new File(tmp,"multee");

        try {
            if( !tc.exists() && !tc.mkdir() )
                throw new IOException("Cannot create "+tc.getAbsolutePath());
            tmpDir = Files.createTempDirectory(tc.toPath(), "jni-").toAbsolutePath().toString() + separator;
            extractResourceDir(tmpDir, nativeLibraries);
            nativeLogger.fine("loading native library");
            System.load(tmpDir + nativeLibraries[0]);

            return loadKeys(keyUriPrefix, keyNames, credentialsZIP);

        } catch (IOException e) {

            return Either.left(MulTeeErrorImpl.of(Errors.ENCLAVE_ARTIFACT_IO,e.getMessage()));

        } finally {
            if( tmpDir != null ) {
                for (String lib : nativeLibraries) {
                    delete(Paths.get(tmpDir).resolve(lib));
                }
                delete(Paths.get(tmpDir));
            }
        }
    }

    private static void delete(Path p) {
        try {
            Files.delete(p);
        } catch (IOException ignored) {}
    }

    private Native(final Long enclaveRef) {
        this.enclaveRef = enclaveRef;
    }

    @SuppressWarnings("deprecation")
    protected void finalize() {
        destroyEnclave(enclaveRef);
    }


    private static native Either<MulTeeError,Long> loadKeys(String url, String[] keyNames, String credsZip);

    private static native void destroyEnclave(long enclaveRef);

    private static native Either<MulTeeError,None<Void>> generateCSR(long enclaveRef, String csrZipFile, String SN);

    private static native Either<MulTeeError,byte[]> hmacSha256(long enclaveRef, int keyIndex, byte[] data);

    private static native Either<MulTeeError,byte[]> cryptCbc(long enclaveRef, int keyIndex, boolean encrypt, boolean explicitIV, byte[] iv, byte[] data);

    private static native Either<MulTeeError,byte[]> cryptGcm(long enclaveRef, int keyIndex, boolean encrypt, byte[] iv, byte[] aad, byte[] data, byte[] tag);

    private static native Either<MulTeeError,Long> getLength(long enclaveRef, int keyIndex);

    private static native Either<MulTeeError,String> getName(long enclaveRef, int keyIndex);

    private static native Either<MulTeeError,byte[]> sign(long enclaveRef, int keyIndex, byte[] data);

    private static native Either<MulTeeError,Boolean> verify(long enclaveRef, int keyIndex, byte[] message, byte[] signature);

    private static void extractResourceDir(String tmpDir, String[] files) throws IOException {
        for (String fileName: files) {
            Path dstPath = Paths.get(tmpDir).resolve(fileName);
            extractFile("/" + fileName, dstPath);
        }
    }

    private static void extractFile(String srcPath, Path dstPath) throws IOException {
        try (InputStream link = Native.class.getResourceAsStream(srcPath)) {
            Files.copy(link, dstPath, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static Either<MulTeeError,String[]> getNativeLibs() {

        if (!"64".equals(System.getProperty("sun.arch.data.model")))
            return Either.left(MulTeeErrorImpl.of(Errors.UNSUPPORTED_PLATFORM,"32-bit Java not supported by MulTee"));
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("mac os x") || os.contains("osx") || os.contains("darwin")) {
            return Either.right(new String[] { "libmultee_jni.dylib" });
        } else if (os.contains("linux")) {


            return Either.right(new String[] { "libmultee_jni.so" });
        }
        return Either.left(MulTeeErrorImpl.of(Errors.UNSUPPORTED_PLATFORM,os + " operation system is not supported by MulTee"));
    }

    Either<MulTeeError,MAC> keyHmacSha256(int keyIndex, byte[] bytes) {
        return hmacSha256(enclaveRef,keyIndex,bytes).map(MAC::of);
    }

    Either<MulTeeError, Tuple2<byte[], IV>> keyCryptCbc(int keyIndex, boolean encrypt, boolean explicitIV, byte[] iv, byte[] data) {
        return cryptCbc(enclaveRef, keyIndex, encrypt, explicitIV, iv, data)
          .map( a-> Tuple.of(a,IV.of(iv)) );
    }

    Either<MulTeeError,byte[]> keyCryptGcm(int keyIndex, boolean encrypt, byte[] iv, byte[] aad, byte[] data, byte[] tag) {
        return cryptGcm(enclaveRef, keyIndex, encrypt, iv, aad, data, tag);
    }

    Either<MulTeeError,Signature> keySign(int keyIndex, byte[] data) {
        return sign(enclaveRef, keyIndex, data).map(Signature::of);
    }

    Either<MulTeeError,Boolean> keyVerify(int keyIndex, byte[] message, byte[] signature) {
        return verify(enclaveRef, keyIndex, message, signature);
    }

    int keyLength(int keyIndex) {
        return getLength(enclaveRef, keyIndex).get().intValue();
    }

    String getName(int keyIndex) {
        return getName(enclaveRef, keyIndex).get();
    }

    Either<MulTeeError,Long> keyLen(int keyIndex) {
        return getLength(enclaveRef, keyIndex);
    }

    Either<MulTeeError,None<Void>> generateCSR(String csrZipFile, String SN) {
        return generateCSR(enclaveRef, csrZipFile, SN);
    }

    public static <T> Either<MulTeeError,T> resultOk(T obj ) {
        return Either.right(obj);
    }

    public static Either<MulTeeError,?> resultErr(int code, int subcode, String msg ) {

        return Either.left(MulTeeErrorImpl.of(code2err.get(code),subcode,msg));
    }
}
