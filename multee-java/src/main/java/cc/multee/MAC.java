package cc.multee;

public class MAC extends WrappedBytes {

    public static MAC of(byte[] bytes) {
        return new MAC(bytes);
    }

    private MAC( byte[] bytes ) {
        super(bytes);
    }
}