package com.bastion.gateway.api;

public class BostainException extends RuntimeException {

    private int err;

    private String errMsg;

    public BostainException(int err, String errMsg){
        this.err = err;
        this.errMsg = errMsg;
    }

    public BostainException(String errMsg){
        this.errMsg = errMsg;
    }

    public int getErr() {
        return err;
    }

    public String getErrMsg() {
        return errMsg;
    }
}
