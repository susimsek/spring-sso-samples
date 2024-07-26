package io.github.susimsek.springauthorizationserver.exception;

import org.springframework.http.HttpStatus;

public class ValidationException extends LocalizedException {

    public ValidationException(String message) {
        super(OAuth2ErrorCode.INVALID_REQUEST.errorCode(), message, HttpStatus.BAD_REQUEST);
    }
}
