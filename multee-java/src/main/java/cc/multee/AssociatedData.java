package cc.multee;

public class AssociatedData extends WrappedBytes {

    public static AssociatedData of(byte[] bytes) {
        return new AssociatedData(bytes);
    }

    private AssociatedData( byte[] bytes ) {
        super(bytes);
    }

    public static AssociatedData without() {
        return new AssociatedData(new byte[0]);
    }
}
