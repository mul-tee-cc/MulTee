package cc.multee;

public class Tag extends WrappedBytes {

    public static Tag of(byte[] bytes) {
        return new Tag(bytes);
    }

    private Tag( byte[] bytes ) {
        super(bytes);
    }
}
