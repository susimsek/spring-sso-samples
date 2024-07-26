package io.github.susimsek.springauthorizationserver.exception.versioning;

public class UnsupportedApiVersionException extends RuntimeException {

    public UnsupportedApiVersionException(String message) {
        super(message);
    }

    public UnsupportedApiVersionException(String message, Throwable cause) {
        super(message, cause);
    }
}
