package cc.multee;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public abstract class MulTeeError {

    public final Errors err;
    protected final int subCode;
    public final String msg;

    public abstract String getFullMsg();

    protected MulTeeError(Errors err, int subCode, String msg) {
        this.err = err;
        this.subCode = subCode;
        this.msg = msg;
    }

    protected static Map<Integer,Errors> code2err() {
        HashMap<Integer,Errors> m = new HashMap<>();
        for( Errors e: Errors.values() ) m.put(e.code,e);
        return Collections.unmodifiableMap(m);
    }
}
