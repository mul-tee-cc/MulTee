package cc.multee;

public class IV extends WrappedBytes {

    public static IV of(byte[] bytes) {
        return new IV(bytes);
    }

    private IV( byte[] bytes ) {
        super(bytes);
    }

    public static IV zero() {
        return new IV(new byte[(int)Const.MULTEE_BLOCK_SIZE]);
    }
}
