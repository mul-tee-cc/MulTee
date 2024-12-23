package cc.multee;

public class WrappedBytes {

    private final byte[] bytes;

//    protected static WrappedBytes of(byte[] bytes) {
//        return new WrappedBytes(bytes);
//    }
//
    protected WrappedBytes( byte[] bytes ) {
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return bytes;
    }
}
