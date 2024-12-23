package cc.multee.sample;

import cc.multee.*;
import cc.multee.impl.MulTeeImpl;

import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.Semaphore;
import java.util.function.Function;
import java.util.regex.*;

import io.vavr.Tuple2;
import io.vavr.Tuple3;
import io.vavr.collection.Set;
import io.vavr.collection.HashSet;
import io.vavr.control.Either;
import static io.vavr.API.*;
import static io.vavr.Patterns.$Left;
import static io.vavr.Patterns.$Right;

public class Main {

    public static void main(String[] args) throws Exception {

        String topUsage = "java -jar java-sample.jar [-h|test-with-key|test-with-all-literal-keys|test-gcm-tag-verification|benchmark] ...";
        String benchUsage = "java -jar java-sample.jar benchmark [CBC|HMAC|Sign] ...";

        Queue<String> argz = new LinkedList<>(Arrays.asList(args));

        usage(argz, 1, topUsage);

        switch (argz.remove()) {
            case "test-gcm-tag-verification":
                usage(argz, 2, "java -jar java-sample.jar test-gcm-tag-verification <Key-URL> <id-credentials.zip>");
                err(getKeyHandle(argz).flatMap(KeyHandle::symmetric));
                break;

            case "test-with-key":
                usage(argz, 2, "java -jar java-sample.jar test-with-key <Key-URL> <id-credentials.zip>");

                Either<MulTeeError, KeyHandle> kh = getKeyHandle(argz);

                switch (kh.get().getName()) {
                    case "HmacKey":
                        hmac(kh.flatMap(KeyHandle::hmac));
                        break;
                    case "TestKey":
                        cbc(kh.flatMap(KeyHandle::symmetric));
                        gcm(kh.flatMap(KeyHandle::symmetric));
                        break;
                    case "EccKey":
                    case "RsaKey":
                        sig(kh.flatMap(KeyHandle::signing));
                        break;
                    default:
                        System.out.println("Unrecognized key name");
                        System.exit(1);
                        break;
                }
                System.out.println("  Tested Ok: true");
                break;

            case "test-with-all-literal-keys":
                usage(argz, 1, "java -jar java-sample.jar test-with-all-literal-keys <id-credentials.zip>");
                String idCredZIP = argz.remove();
                Either<MulTeeError,KeyFactory> kf = MulTeeImpl.getKeyFactory("file://./", HashSet.of( "TestKey", "RsaKey", "EccKey" ), idCredZIP);

                hmac(kf.flatMap(x -> x.getKey("HmacKey")).flatMap(KeyHandle::hmac));
                cbc(kf.flatMap(x -> x.getKey("TestKey")).flatMap(KeyHandle::symmetric));
                gcm(kf.flatMap(x -> x.getKey("TestKey")).flatMap(KeyHandle::symmetric));
                sig(kf.flatMap(x -> x.getKey("RsaKey")).flatMap(KeyHandle::signing));
                sig(kf.flatMap(x -> x.getKey("EccKey")).flatMap(KeyHandle::signing));
                break;
            case "benchmark":
                usage(argz, 3, benchUsage);

                switch (argz.remove()) {
                    case "CBC":
                        usage(argz, 5, "java -jar multee-java.jar benchmark CBC <threads> <cycles> <bytes> <urlStr> <idCredZip>");
                        benchmarkCBC(argz);
                        break;
                    case "HMAC":
                        usage(argz, 5, "java -jar multee-java.jar benchmark HMAC <threads> <cycles> <bytes> <urlStr> <idCredZip>");
                        benchmarkHMAC(argz);
                        break;
                    case "Sign":
                        usage(argz, 4, "java -jar multee-java.jar benchmark Sign <threads> <cycles> <urlStr> <idCredZip>");
                        benchmarkSign(argz);
                        break;
                    default:
                        usage(argz, 99, "Unsupported benchmark type");
                }

                break;

            default:
                usage(argz, 2, "java -jar java-sample.jar [-h|test-with-key|test-with-all-literal-keys|test-gcm-tag-verification|benchmark] ...");
        }
    }

    ///////////////////////////////////////////
    // Functional style tests
    ///////////////////////////////////////////

    private static void sig( Either<MulTeeError,SigningKey> key ) {

        String testMsg = "testMsg";
        byte[] testBytes  = testMsg.getBytes();

        Either<MulTeeError,Signature> result =
                key.flatMap( k -> k.sign(testBytes));

        Signature _sig =
        Match(result).of(
                Case($Left($()), err ->{
                    throw new RuntimeException("Broken test?");
                }),
                Case($Right($()), sig-> {
                    System.out.println("Message: "+testMsg);
                    System.out.println("Signed: "+toBase64(sig.getBytes()));
                    System.out.println();
                    return sig;
                })
        );
    }

    private static void hmac( Either<MulTeeError,HMACKey> key ) {

        String testMsg = "testMsg";
        byte[] testBytes  = testMsg.getBytes();

        Either<MulTeeError,MAC> result = key.flatMap( k -> k.hmacSHA256(testBytes));

        MAC _mac =
            Match(result).of(
                Case($Left($()), err ->{
                    throw new RuntimeException("Broken test?");
                }),
                Case($Right($()), mac -> {
                    System.out.println("Message: "+testMsg);
                    System.out.println("HMAC: "+toBase64(mac.getBytes()));
                    System.out.println();
                    return mac;
                })
            );

    }

    private static void cbc( Either<MulTeeError,SymmetricKey> key ) {

        String testMsg = "testMsg";
        byte[] testBytes  = testMsg.getBytes();

        Either<MulTeeError,Tuple2<byte[],IV>> result = key.flatMap( k -> k.encryptCBC(testBytes));

        Match(result).of(
            Case($Left($()), err ->{
                throw new RuntimeException("Broken test?");
            }),
            Case($Right($()), ciphertext -> {
                System.out.println("Message: "+testMsg);
                System.out.println("CBC ciphertext: "+toBase64(ciphertext._1));
                System.out.println("CBC IV: "+toBase64(ciphertext._2.getBytes()));
                System.out.println();
                return ciphertext;
            })
        );
    }

    private static void gcm( Either<MulTeeError,SymmetricKey> key ) {

        String testMsg = "testMsg";
        byte[] testBytes  = testMsg.getBytes();

        Either<MulTeeError,Tuple3<byte[],IV,Tag>> result = key.flatMap( k -> k.seal(testBytes));

        Match(result).of(
            Case($Left($()), err ->{
                throw new RuntimeException("Broken test?");
            }),
            Case($Right($()), ciphertext -> {
                System.out.println("Message: "+testMsg);
                System.out.println("GCM ciphertext: "+toBase64(ciphertext._1));
                System.out.println("GCM IV: "+toBase64(ciphertext._2.getBytes()));
                System.out.println("GCM Tag: "+toBase64(ciphertext._3.getBytes()));
                System.out.println();
                return ciphertext;
            })
        );
    }

    private static void err( Either<MulTeeError,SymmetricKey> key ) {

        String testMsg = "testMsg";
        byte[] testBytes  = testMsg.getBytes();

        Either<MulTeeError,byte[]> result = key
            .flatMap( k ->k.seal(testBytes)
                .flatMap( ciphertext -> k.unseal( corrupt(ciphertext._1), ciphertext._2, ciphertext._3 ) ));



        Match(result).of(
            Case($Left($()), err -> {
                System.out.println("Error code: "+err.err);
                System.out.println("Is tag verification error: "+ (err.err == Errors.CRYPTO_AUTH_TAG_VERIFY_FAILED));
                System.out.println("Error message: "+(err.msg.isEmpty() ? "Empty" : err.msg) );
                System.out.println("\n> > Rethrowing < <\n");
                MulTeeException.unwrap(result);
                throw new RuntimeException("Unreachable");
            }),
            Case($Right($()), ciphertext -> {
                throw new RuntimeException("Broken test?");
            })
        );
    }

    ///////////////////////////////////////////
    // Benchmarks
    ///////////////////////////////////////////

    private static void benchmarkCBC(Queue<String> argz) throws Exception {


        int threads = Integer.parseInt( argz.remove() );
        int cycles = Integer.parseInt( argz.remove() );
        int bytes_num = Integer.parseInt( argz.remove() );

        SymmetricKey key = MulTeeException.unwrap(getKeyHandle(argz).flatMap(KeyHandle::symmetric));

        Callable<byte[]> byteMaker = () -> mkBytes(bytes_num);

        IV iv = IV.zero();

        Function<byte[], Either<MulTeeError,?>> cbc = b -> key.encryptCBC(b,iv);

        bench(threads, 10000, byteMaker, cbc, true);
        bench(threads, cycles, byteMaker, cbc, false);
    }

    private static void benchmarkHMAC(Queue<String> argz) throws Exception {

        int threads = Integer.parseInt( argz.remove() );
        int cycles = Integer.parseInt( argz.remove() );
        int bytes_num = Integer.parseInt( argz.remove() );

        HMACKey key = MulTeeException.unwrap(getKeyHandle(argz).flatMap(KeyHandle::hmac));

        Callable<byte[]> byteMaker = () -> mkBytes(bytes_num);

        bench(threads, 10000, byteMaker, key::hmacSHA256, true);
        bench(threads, cycles, byteMaker, key::hmacSHA256, false);
    }

    private static void benchmarkSign(Queue<String> argz) throws Exception {

        int threads = Integer.parseInt( argz.remove() );
        int cycles = Integer.parseInt( argz.remove() );

        SigningKey key = MulTeeException.unwrap(getKeyHandle(argz).flatMap(KeyHandle::signing));

        Callable<byte[]> byteMaker = () -> mkBytes(32);

        Function<byte[], Either<MulTeeError,?>> sign = key::sign;

        bench(threads, 2000, byteMaker, key::sign, true);
        bench(threads, cycles,  byteMaker, key::sign, false);
    }

    private static  void bench(int threads, int cycles, Callable<byte[]> mkBytes, Function<byte[], Either<MulTeeError,?>> cryptoOp, boolean warmup ) throws Exception {

        if( warmup ) threads = 1;

        Semaphore entry1 = new Semaphore( 0 );
        Semaphore entry2 = new Semaphore( 0 );
        Semaphore exit   = new Semaphore( 0 );

        for( int i = 0; i < threads; i++ )
            new Thread( () -> {
                try {

                    byte[] bytes = mkBytes.call();

                    entry1.release();
                    entry2.acquire();

                    for( int j = 0; j < cycles; j++ ) cryptoOp.apply(bytes);

                    exit.release();

                } catch( Exception e ) {
                    System.out.println( "RuntimeException( e )" );
                    throw new RuntimeException( e );
                }
            } ).start();

        entry1.acquire( threads );

        System.out.println( warmup ? "warmup" : "go" );

        long start = System.nanoTime();
        entry2.release( threads );

        exit.acquire( threads );
        long rt = System.nanoTime();

        if( !warmup ) {
            System.out.println("Rounds: " + cycles);
            System.out.println("Runtime (ms): " + (rt - start) / 1000000.0);
            System.out.println("op/s: " + cycles * 1000000000l / (rt - start));
        }
    }

    ///////////////////////////////////////////
    // Java style tests
    ///////////////////////////////////////////

    private static void testSig( String[] args ) {

        String urlStr = args[0];
        String idCredZip = args[1];

        KeyURL url = new KeyURL( urlStr );
        String urlPrefix = url.getURLPrefix();
        String keyName = url.getKeyName();
        Set<String> keys = HashSet.of( keyName );

        KeyFactory kf = MulTeeException.unwrap(MulTeeImpl.getKeyFactory( urlPrefix, keys, idCredZip));
        KeyHandle kh = MulTeeException.unwrap(kf.getKey(keyName));

        SigningKey key = MulTeeException.unwrap(kh.signing());

        String testMsg = "testMsg";
        byte[] testBytes  = testMsg.getBytes();

        System.out.println("KeyLen: "+key.getLength());
        System.out.println("Message: "+testMsg);
        Signature sig = MulTeeException.unwrap(key.sign(testBytes));
        System.out.println("Signed: "+toBase64(sig.getBytes()));

        Boolean vResult = MulTeeException.unwrap(key.getPublicKey().verify(testBytes,sig));
        System.out.println("Verified: "+vResult);
    }

    private static void testHMAC( String[] args ) {
        String urlStr = args[0];
        String idCredZip = args[1];

        KeyURL url = new KeyURL( urlStr );
        String urlPrefix = url.getURLPrefix();
        String keyName = url.getKeyName();
        Set<String> keys = HashSet.of( keyName );

        KeyFactory kf = MulTeeException.unwrap(MulTeeImpl.getKeyFactory( urlPrefix, keys, idCredZip));
        KeyHandle kh = MulTeeException.unwrap(kf.getKey(keyName));

        HMACKey key = MulTeeException.unwrap(kh.hmac());

        String testMsg = "testMsg";
        byte[] testBytes  = testMsg.getBytes();

        System.out.println("KeyLen: "+key.getLength());
        System.out.println("Message: "+testMsg);
        System.out.println("Encoded: "+toBase64(testBytes));
        System.out.println("HMAC");
        MAC mac = MulTeeException.unwrap(key.hmacSHA256(testBytes));
        System.out.println("  hmac256: " + toBase64(mac.getBytes()));
    }

    private static void testCBC1( String[] args ) {

        String urlStr = args[0];
        String idCredZip = args[1];

        KeyURL url = new KeyURL( urlStr );
        String urlPrefix = url.getURLPrefix();
        String keyName = url.getKeyName();
        Set<String> keys = HashSet.of( keyName );

        KeyFactory kf = MulTeeException.unwrap(MulTeeImpl.getKeyFactory( urlPrefix, keys, idCredZip));
        KeyHandle kh = MulTeeException.unwrap(kf.getKey(keyName));

        SymmetricKey key = MulTeeException.unwrap(kh.symmetric());

        String testMsg = "testMsg";
        byte[] testBytes  = testMsg.getBytes();

        System.out.println("KeyLen: "+key.getLength());
        System.out.println("Message: "+testMsg);
        System.out.println("Encoded: "+toBase64(testBytes));
        System.out.println("CBC random IV");
        Tuple2<byte[], IV> cypherText = MulTeeException.unwrap(key.encryptCBC(testBytes));
        System.out.println("  Encrypted: " + toBase64(cypherText._1));
        System.out.println("  IV: " + toBase64(cypherText._2.getBytes()));
        Either<MulTeeError, byte[]> plaintext = key.decryptCBC(cypherText._1, cypherText._2);
        System.out.println("  Decrypted: " + new String(plaintext.get()));
        System.out.println("  Decrypted correctly: " + testMsg.equals(new String(plaintext.get())));
    }

    private static void testCBC2( String[] args ) {

        String urlStr = args[0];
        String idCredZip = args[1];

        KeyURL url = new KeyURL( urlStr );
        String urlPrefix = url.getURLPrefix();
        String keyName = url.getKeyName();
        Set<String> keys = HashSet.of( keyName );

        KeyFactory kf = MulTeeException.unwrap(MulTeeImpl.getKeyFactory( urlPrefix, keys, idCredZip));
        KeyHandle kh = MulTeeException.unwrap(kf.getKey(keyName));

        SymmetricKey key = MulTeeException.unwrap(kh.symmetric());

        String testMsg = "testMsg";
        byte[] testBytes  = testMsg.getBytes();

        System.out.println("KeyLen: "+key.getLength());
        System.out.println("Message: "+testMsg);
        System.out.println("Encoded: "+toBase64(testBytes));
        System.out.println("CBC explicit IV");
        Tuple2<byte[], IV> cypherText = MulTeeException.unwrap(key.encryptCBC(testBytes,IV.zero()));
        System.out.println("  Encrypted: " + toBase64(cypherText._1));
        System.out.println("  IV: " + toBase64(cypherText._2.getBytes()));
        Either<MulTeeError, byte[]> plaintext = key.decryptCBC(cypherText._1, cypherText._2);
        System.out.println("  Decrypted: " + new String(plaintext.get()));
        System.out.println("  Decrypted correctly: " + testMsg.equals(new String(plaintext.get())));
    }

    private static void testGCM( String[] args ) {

        String urlStr = args[0];
        String idCredZip = args[1];

        KeyURL url = new KeyURL( urlStr );
        String urlPrefix = url.getURLPrefix();
        String keyName = url.getKeyName();
        Set<String> keys = HashSet.of( keyName );

        KeyFactory kf = MulTeeException.unwrap(MulTeeImpl.getKeyFactory( urlPrefix, keys, idCredZip));
        KeyHandle kh = MulTeeException.unwrap(kf.getKey(keyName));

        SymmetricKey key = MulTeeException.unwrap(kh.symmetric());

        String testMsg = "testMsg";
        byte[] testBytes  = testMsg.getBytes();

        System.out.println("KeyLen: "+key.getLength());
        System.out.println("Message: "+testMsg);
        System.out.println("Encoded: "+toBase64(testBytes));
        System.out.println("GCM");
        Tuple3<byte[], IV, Tag> cypherText = MulTeeException.unwrap(key.seal(testBytes));
        System.out.println("  Encrypted: " + toBase64(cypherText._1));
        System.out.println("  IV: " + toBase64(cypherText._2.getBytes()));
        System.out.println("  Tag: " + toBase64(cypherText._3.getBytes()));
        Either<MulTeeError, byte[]> plaintext = key.unseal(cypherText._1, cypherText._2, cypherText._3);
        System.out.println("  Decrypted: " + new String(plaintext.get()));
        System.out.println("  Decrypted correctly: " + testMsg.equals(new String(plaintext.get())));
    }

    ///////////////////////////////////////////
    // Helper functions
    ///////////////////////////////////////////

    private static byte[] mkBytes(int bytes_num) {
        byte[] bytes = new byte[bytes_num];
        new Random().nextBytes( bytes );
        return bytes;
    }

    private static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static byte[] corrupt(byte[] array) {
        array[0] = (byte) (array[0]^1);
        return array;
    }

    private static class KeyURL {

        private final String keyName;
        private final String urlPath;
        private static final Pattern urlP = Pattern.compile("(.+/)([^/]+)");

        public KeyURL( String URL ) {

            java.net.URI u = java.net.URI.create(URL);

            if( !u.getScheme().equals("kmip") && !u.getScheme().equals("vault")  && !u.getScheme().equals("file") )
                throw new IllegalArgumentException( "Malformed key URL: "+URL );

            Matcher m = urlP.matcher( URL );
            if( !m.matches() )
                throw new IllegalArgumentException( "Malformed key URL: "+URL );

            urlPath = m.group( 1 );
            keyName = m.group( 2 );
        }

        public String getKeyName() {return keyName;}
        public String getURLPrefix() {return urlPath;}
    }

    private static Either<MulTeeError, KeyHandle> getKeyHandle(Queue<String> argz ) {

        String urlStr = argz.remove();
        String idCredZip = argz.remove();

        KeyURL url = new KeyURL( urlStr );
        String urlPrefix = url.getURLPrefix();
        String keyName = url.getKeyName();
        Set<String> keys = HashSet.of( keyName );

        return MulTeeImpl.getKeyFactory( urlPrefix, keys, idCredZip).flatMap( kf -> kf.getKey(keyName));
    }

    private static Either<MulTeeError, KeyHandle> getLiteralKeyHandle(String keyName, String idZIP ) {
        return MulTeeImpl.getKeyFactory( "file://./", HashSet.of( keyName ), idZIP).flatMap( kf -> kf.getKey(keyName));
    }

    private static void usage( Queue<String> args, int needed, String msg ) {
        if( args.size() < needed || "-h".equals(args.peek()) ) {
            System.out.println(msg);
            System.exit(1);
        }
    }

}
