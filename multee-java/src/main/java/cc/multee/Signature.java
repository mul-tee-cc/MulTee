package cc.multee;

public class Signature extends WrappedBytes {

    public static Signature of(byte[] bytes) {
        return new Signature(bytes);
    }

    private Signature( byte[] bytes ) {
        super(bytes);
    }
}