package com.feng.samltest.exception;

public class SamlException extends Exception {
    public SamlException(String message) {
        super(message);
    }

    public SamlException(String message, Throwable cause) {
        super(message, cause);
    }
}
