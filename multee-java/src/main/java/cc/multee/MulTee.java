package cc.multee;

import cc.multee.impl.MulTeeImpl;
import java.util.Set;
import io.vavr.control.Either;
import java.io.InputStream;

public class MulTee {
    public static Either<MulTeeError,KeyFactory> getKeyFactory(String keyUriPrefix, Set<String> keyNames, String idCcredentials) {
        return MulTeeImpl.getKeyFactory(keyUriPrefix, toVavr(keyNames), idCcredentials);
    }
    public static Either<MulTeeError,KeyFactory> getKeyFactory(String keyUriPrefix, Set<String> keyNames, InputStream idCcredentials ) {
        return MulTeeImpl.getKeyFactory(keyUriPrefix, toVavr(keyNames), idCcredentials);
    }

    private static io.vavr.collection.Set<String> toVavr(Set<String> set) {
        return io.vavr.collection.HashSet.ofAll(set);
    }
}
