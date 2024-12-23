package cc.multee;

import io.vavr.control.Either;


/**
 *
 */
public class MulTeeException extends RuntimeException {

    public final MulTeeError err;

    MulTeeException(final MulTeeError err ) {
        super(err.getFullMsg());
        this.err = err;
    }

    public static <T> T unwrap(Either<MulTeeError,T> e) {
        if( e.isRight() ) {
            return e.get();
        } else {
            throw new MulTeeException(e.getLeft());
        }
    }
}
