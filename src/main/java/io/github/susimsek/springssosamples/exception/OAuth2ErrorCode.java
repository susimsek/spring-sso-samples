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
    INVALID_REDIRECT_URI("invalid_redirect_uri", HttpStatus.BAD_REQUEST, "error.oauth2.invalid_redirect_uri"),
    MEDIA_TYPE_NOT_ACCEPTABLE("invalid_request", HttpStatus.NOT_ACCEPTABLE, "error.oauth2.media_type_not_acceptable"),
    MEDIA_TYPE_NOT_SUPPORTED("invalid_request", HttpStatus.UNSUPPORTED_MEDIA_TYPE, "error.oauth2.media_type_not_supported"),
    REQUEST_METHOD_NOT_SUPPORTED("invalid_request", HttpStatus.METHOD_NOT_ALLOWED, "error.oauth2.request_method_not_supported"),
    MESSAGE_NOT_READABLE("invalid_request", HttpStatus.BAD_REQUEST, "error.oauth2.message_not_readable"),
    TYPE_MISMATCH("invalid_request", HttpStatus.BAD_REQUEST, "error.oauth2.type_mismatch"),
    MISSING_PARAMETER("invalid_request", HttpStatus.BAD_REQUEST, "error.oauth2.missing_parameter"),
    MISSING_PART("invalid_request", HttpStatus.BAD_REQUEST, "error.oauth2.missing_part"),
    REQUEST_BINDING_ERROR("invalid_request", HttpStatus.BAD_REQUEST, "error.oauth2.request_binding_error"),
    MULTIPART_ERROR("invalid_request", HttpStatus.BAD_REQUEST, "error.oauth2.multipart_error"),
    VALIDATION_ERROR("invalid_request", HttpStatus.BAD_REQUEST, "error.oauth2.validation"),
    NO_HANDLER_FOUND("invalid_request", HttpStatus.NOT_FOUND, "error.oauth2.no_handler_found"),
    UNSUPPORTED_OPERATION("unsupported_operation", HttpStatus.NOT_IMPLEMENTED, "error.oauth2.unsupported_operation"),
    GATEWAY_TIMEOUT("gateway_timeout", HttpStatus.GATEWAY_TIMEOUT, "error.oauth2.gateway_timeout");


    private final String errorCode;
    private final HttpStatus httpStatus;
    private final String messageKey;

    public static Optional<OAuth2ErrorCode> fromErrorCode(String errorCode) {
        return Arrays.stream(values())
                     .filter(code -> code.errorCode().equals(errorCode))
                     .findFirst();
    }
}
