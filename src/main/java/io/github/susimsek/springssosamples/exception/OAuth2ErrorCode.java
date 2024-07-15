package io.github.susimsek.springssosamples.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import org.springframework.http.HttpStatus;

import java.util.Arrays;
import java.util.Optional;

@Getter
@Accessors(fluent = true)
@RequiredArgsConstructor
public enum OAuth2ErrorCode {
    INVALID_REQUEST("invalid_request", HttpStatus.BAD_REQUEST, "error.oauth2.invalid_request"),
    UNAUTHORIZED_CLIENT("unauthorized_client", HttpStatus.UNAUTHORIZED, "error.oauth2.unauthorized_client"),
    ACCESS_DENIED("access_denied", HttpStatus.FORBIDDEN, "error.oauth2.access_denied"),
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type", HttpStatus.BAD_REQUEST, "error.oauth2.unsupported_response_type"),
    INVALID_SCOPE("invalid_scope", HttpStatus.BAD_REQUEST, "error.oauth2.invalid_scope"),
    INSUFFICIENT_SCOPE("insufficient_scope", HttpStatus.FORBIDDEN, "error.oauth2.insufficient_scope"),
    INVALID_TOKEN("invalid_token", HttpStatus.UNAUTHORIZED, "error.oauth2.invalid_token"),
    SERVER_ERROR("server_error", HttpStatus.INTERNAL_SERVER_ERROR, "error.oauth2.server_error"),
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable", HttpStatus.SERVICE_UNAVAILABLE, "error.oauth2.temporarily_unavailable"),
    INVALID_CLIENT("invalid_client", HttpStatus.UNAUTHORIZED, "error.oauth2.invalid_client"),
    INVALID_GRANT("invalid_grant", HttpStatus.BAD_REQUEST, "error.oauth2.invalid_grant"),
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type", HttpStatus.BAD_REQUEST, "error.oauth2.unsupported_grant_type"),
    UNSUPPORTED_TOKEN_TYPE("unsupported_token_type", HttpStatus.BAD_REQUEST, "error.oauth2.unsupported_token_type"),
    INVALID_REDIRECT_URI("invalid_redirect_uri", HttpStatus.BAD_REQUEST, "error.oauth2.invalid_redirect_uri");

    private final String errorCode;
    private final HttpStatus httpStatus;
    private final String messageKey;

    public static Optional<OAuth2ErrorCode> fromErrorCode(String errorCode) {
        return Arrays.stream(values())
                     .filter(code -> code.errorCode().equals(errorCode))
                     .findFirst();
    }
}
