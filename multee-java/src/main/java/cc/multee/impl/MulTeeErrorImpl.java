package cc.multee.impl;

import cc.multee.MulTeeError;
import cc.multee.Errors;

import java.util.Map;

class MulTeeErrorImpl extends MulTeeError {

    protected MulTeeErrorImpl(Errors err, int subCode, String msg) {
        super(err, subCode, msg);
    }

    static Map<Integer,Errors> getCode2err() {
        return code2err();
    }

        @Override
    public String getFullMsg() {

        return super.err.name()+"{"+super.subCode+"}: "+super.msg;
    }

    public static MulTeeError of(Errors err, String msg) {
        return new MulTeeErrorImpl( err, 0, msg );
    }

    public static MulTeeError of(Errors err, int subCode, String msg) {
        return new MulTeeErrorImpl( err, subCode, msg );
    }
}
