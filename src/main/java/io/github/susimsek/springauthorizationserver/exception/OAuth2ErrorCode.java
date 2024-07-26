package io.github.susimsek.springauthorizationserver.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import org.springframework.http.HttpStatus;

import java.util.Arrays;
import java.util.Optional;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

@Getter
@Accessors(fluent = true)
@RequiredArgsConstructor
public enum OAuth2ErrorCode {
    INVALID_REQUEST(OAuth2ErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST, "error.oauth2.invalid_request"),
    UNAUTHORIZED_CLIENT(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, HttpStatus.UNAUTHORIZED, "error.oauth2.unauthorized_client"),
    ACCESS_DENIED(OAuth2ErrorCodes.ACCESS_DENIED, HttpStatus.FORBIDDEN, "error.oauth2.access_denied"),
    UNSUPPORTED_RESPONSE_TYPE(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, HttpStatus.BAD_REQUEST, "error.oauth2.unsupported_response_type"),
    INVALID_SCOPE(OAuth2ErrorCodes.INVALID_SCOPE, HttpStatus.BAD_REQUEST, "error.oauth2.invalid_scope"),
    INSUFFICIENT_SCOPE(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, HttpStatus.FORBIDDEN, "error.oauth2.insufficient_scope"),
    INVALID_TOKEN(OAuth2ErrorCodes.INVALID_TOKEN, HttpStatus.UNAUTHORIZED, "error.oauth2.invalid_token"),
    SERVER_ERROR(OAuth2ErrorCodes.SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, "error.oauth2.server_error"),
    TEMPORARILY_UNAVAILABLE(OAuth2ErrorCodes.TEMPORARILY_UNAVAILABLE, HttpStatus.SERVICE_UNAVAILABLE, "error.oauth2.temporarily_unavailable"),
    INVALID_CLIENT(OAuth2ErrorCodes.INVALID_CLIENT, HttpStatus.UNAUTHORIZED, "error.oauth2.invalid_client"),
    INVALID_GRANT(OAuth2ErrorCodes.INVALID_GRANT, HttpStatus.BAD_REQUEST, "error.oauth2.invalid_grant"),
    UNSUPPORTED_GRANT_TYPE(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, HttpStatus.BAD_REQUEST, "error.oauth2.unsupported_grant_type"),
    UNSUPPORTED_TOKEN_TYPE(OAuth2ErrorCodes.UNSUPPORTED_TOKEN_TYPE, HttpStatus.BAD_REQUEST, "error.oauth2.unsupported_token_type"),
    INVALID_REDIRECT_URI(OAuth2ErrorCodes.INVALID_REDIRECT_URI, HttpStatus.BAD_REQUEST, "error.oauth2.invalid_redirect_uri"),
    NOT_ACCEPTABLE("not_acceptable", HttpStatus.NOT_ACCEPTABLE, "error.oauth2.not_acceptable"),
    UNSUPPORTED_MEDIA_TYPE("unsupported_media_type", HttpStatus.UNSUPPORTED_MEDIA_TYPE, "error.oauth2.unsupported_media_type"),
    METHOD_NOT_ALLOWED("method_not_allowed", HttpStatus.METHOD_NOT_ALLOWED, "error.oauth2.method_not_allowed"),
    MESSAGE_NOT_READABLE(OAuth2ErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST, "error.oauth2.message_not_readable"),
    TYPE_MISMATCH(OAuth2ErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST, "error.oauth2.type_mismatch"),
    MISSING_PARAMETER(OAuth2ErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST, "error.oauth2.missing_parameter"),
    MISSING_PART(OAuth2ErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST, "error.oauth2.missing_part"),
    REQUEST_BINDING(OAuth2ErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST, "error.oauth2.request_binding"),
    MULTIPART(OAuth2ErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST, "error.oauth2.multipart"),
    VALIDATION_FAILED(OAuth2ErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST, "error.oauth2.validation_failed"),
    NOT_FOUND("resource_not_found", HttpStatus.NOT_FOUND, "error.oauth2.not_found"),
    UNSUPPORTED_OPERATION("unsupported_operation", HttpStatus.NOT_IMPLEMENTED, "error.oauth2.unsupported_operation"),
    GATEWAY_TIMEOUT("gateway_timeout", HttpStatus.GATEWAY_TIMEOUT, "error.oauth2.gateway_timeout"),
    RATE_LIMIT_EXCEEDED("rate_limit_exceeded", HttpStatus.TOO_MANY_REQUESTS, "error.oauth2.rate_limit_exceeded"),
    UNSUPPORTED_API_VERSION("unsupported_api_version", HttpStatus.GATEWAY_TIMEOUT, "error.oauth2.unsupported_api_version");


    private final String errorCode;
    private final HttpStatus httpStatus;
    private final String messageKey;

    public static Optional<OAuth2ErrorCode> fromErrorCode(String errorCode) {
        return Arrays.stream(values())
                     .filter(code -> code.errorCode().equals(errorCode))
                     .findFirst();
    }
}
