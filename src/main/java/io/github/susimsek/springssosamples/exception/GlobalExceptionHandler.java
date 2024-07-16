package io.github.susimsek.springssosamples.exception;

import static io.github.susimsek.springssosamples.exception.ratelimit.RateLimitConstants.RATE_LIMIT_LIMIT_HEADER_NAME;
import static io.github.susimsek.springssosamples.exception.ratelimit.RateLimitConstants.RATE_LIMIT_REMAINING_HEADER_NAME;
import static io.github.susimsek.springssosamples.exception.ratelimit.RateLimitConstants.RATE_LIMIT_RESET_HEADER_NAME;

import io.github.susimsek.springssosamples.exception.ratelimit.RateLimitExceededException;
import io.github.susimsek.springssosamples.exception.versioning.UnsupportedApiVersionException;
import io.github.susimsek.springssosamples.i18n.ParameterMessageSource;
import jakarta.validation.ConstraintViolationException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.TypeMismatchException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.lang.NonNull;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.util.StringUtils;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
@RequiredArgsConstructor
@Slf4j
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private final ParameterMessageSource messageSource;

    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotAcceptable(
        @NonNull HttpMediaTypeNotAcceptableException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.NOT_ACCEPTABLE;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(
        @NonNull HttpMediaTypeNotSupportedException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.UNSUPPORTED_MEDIA_TYPE;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(
        @NonNull HttpRequestMethodNotSupportedException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.METHOD_NOT_ALLOWED;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(
        @NonNull HttpMessageNotReadableException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.MESSAGE_NOT_READABLE;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleTypeMismatch(
        @NonNull TypeMismatchException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.TYPE_MISMATCH;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(
        @NonNull MissingServletRequestParameterException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        Map<String, Object> namedArgs = Map.of("paramName", ex.getParameterName());
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.MISSING_PARAMETER;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            namedArgs, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestPart(
        @NonNull MissingServletRequestPartException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        Map<String, Object> namedArgs = Map.of("partName", ex.getRequestPartName());
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.MISSING_PART;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            namedArgs, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleServletRequestBindingException(
        @NonNull ServletRequestBindingException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.REQUEST_BINDING;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, new HttpHeaders(), request);
    }

    @ExceptionHandler(MultipartException.class)
    protected ResponseEntity<Object> handleMultipartException(@NonNull MultipartException ex,
                                                              @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.MULTIPART;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
        @NonNull MethodArgumentNotValidException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        List<Violation> violations = Stream.concat(
            ex.getFieldErrors().stream().map(Violation::new),
            ex.getGlobalErrors().stream().map(Violation::new)
        ).toList();

        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.VALIDATION_FAILED;
        ProblemDetail problem = createProblemDetail(new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, request);
        problem.setProperty(ErrorConstants.PROBLEM_VIOLATION_KEY, violations);
        return handleExceptionInternal(ex, problem, headers, oAuth2ErrorCode.httpStatus(), request);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    protected ResponseEntity<Object> handleConstraintViolationException(
        @NonNull ConstraintViolationException ex,
        @NonNull WebRequest request) {
        List<Violation> violations = ex.getConstraintViolations().stream().map(Violation::new).toList();

        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.VALIDATION_FAILED;
        ProblemDetail problem = createProblemDetail(new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, request);
        problem.setProperty(ErrorConstants.PROBLEM_VIOLATION_KEY, violations);
        return handleExceptionInternal(ex, problem, new HttpHeaders(), oAuth2ErrorCode.httpStatus(), request);
    }

    @ExceptionHandler(AuthenticationException.class)
    protected ResponseEntity<Object> handleAuthentication(@NonNull AuthenticationException ex,
                                                          @NonNull WebRequest request) {
        if (ex instanceof OAuth2AuthenticationException oAuth2AuthenticationException) {
            OAuth2Error oAuth2Error = oAuth2AuthenticationException.getError();
            var optionalOAuth2ErrorCode = OAuth2ErrorCode.fromErrorCode(oAuth2Error.getErrorCode());
            if (optionalOAuth2ErrorCode.isPresent()) {
                OAuth2ErrorCode oAuth2ErrorCode = optionalOAuth2ErrorCode.get();
                return createProblemDetailResponse(ex, oAuth2Error,
                    oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
                    null, new HttpHeaders(), request);
            }
        }
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.INVALID_TOKEN;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, new HttpHeaders(), request);
    }

    @ExceptionHandler(AccessDeniedException.class)
    protected ResponseEntity<Object> handleAccessDenied(@NonNull AccessDeniedException ex,
                                                        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.ACCESS_DENIED;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleNoHandlerFoundException(
        @NonNull NoHandlerFoundException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.NO_HANDLER_FOUND;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, new HttpHeaders(), request);
    }

    @ExceptionHandler(RateLimitExceededException.class)
    protected ResponseEntity<Object> handleRateLimitExceededException(
        @NonNull RateLimitExceededException ex,
        @NonNull WebRequest request) {

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.RETRY_AFTER, String.valueOf(ex.getWaitTime()));
        headers.add(RATE_LIMIT_LIMIT_HEADER_NAME, String.valueOf(ex.getLimitForPeriod()));
        headers.add(RATE_LIMIT_REMAINING_HEADER_NAME, String.valueOf(ex.getAvailablePermissions()));
        headers.add(RATE_LIMIT_RESET_HEADER_NAME, String.valueOf(ex.getResetTime()));

        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.RATE_LIMIT_EXCEEDED;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, headers, request);
    }

    @ExceptionHandler(UnsupportedOperationException.class)
    public ResponseEntity<Object> handleUnsupportedOperationException(
        @NonNull UnsupportedOperationException ex,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.UNSUPPORTED_OPERATION;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey()
            , null, new HttpHeaders(), request);
    }

    @ExceptionHandler(UnsupportedApiVersionException.class)
    public ResponseEntity<Object> handleUnsupportedApiVersionException(
        @NonNull UnsupportedApiVersionException ex,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.UNSUPPORTED_API_VERSION;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey()
            , null, new HttpHeaders(), request);
    }

    @ExceptionHandler(SocketTimeoutException.class)
    public ResponseEntity<Object> handleSocketTimeoutException(@NonNull SocketTimeoutException ex,
                                                               @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.GATEWAY_TIMEOUT;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, new HttpHeaders(), request);
    }

    @ExceptionHandler(ResourceException.class)
    public ResponseEntity<Object> handleResourceException(@NonNull ResourceException ex,
                                                          @NonNull WebRequest request) {
        Locale locale = request.getLocale();
        String localizedResourceName = messageSource.getMessage(
            "resource." + ex.getResourceName().toLowerCase(), null, locale);
        String searchCriteria = messageSource.getMessage(
            "search.criteria." + ex.getSearchCriteria().toLowerCase(), null, locale);
        Map<String, Object> namedArgs = createNamedArgs(
            localizedResourceName, searchCriteria, ex.getSearchValue());
        return createProblemDetailResponse(ex, new OAuth2Error(ex.getErrorCode()),
            ex.getStatus(), ex.getMessage(),
            namedArgs, new HttpHeaders(), request);
    }


    @ExceptionHandler(LocalizedException.class)
    public ResponseEntity<Object> handleLocalizedException(@NonNull LocalizedException ex,
                                                           @NonNull WebRequest request) {
        return createProblemDetailResponse(ex, new OAuth2Error(ex.getErrorCode()),
            ex.getStatus(), ex.getMessage(),
            null, new HttpHeaders(), request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleAllExceptions(
        @NonNull Exception ex,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.SERVER_ERROR;
        return createProblemDetailResponse(ex, new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode.httpStatus(), oAuth2ErrorCode.messageKey(),
            null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(
        @NonNull Exception ex,
        Object body,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        log.error("An exception occurred, which will cause a {} response", status, ex);
        return super.handleExceptionInternal(ex, body, headers, status, request);
    }

    private ResponseEntity<Object> createProblemDetailResponse(
        Exception ex,
        OAuth2Error oAuth2Error,
        HttpStatusCode httpStatus,
        String messageKey,
        Map<String, Object> namedArgs,
        HttpHeaders headers,
        WebRequest request) {
        ProblemDetail problem = createProblemDetail(
            oAuth2Error,
            httpStatus,
            messageKey,
            namedArgs, request);
        return handleExceptionInternal(ex, problem, headers, httpStatus, request);
    }

    private ProblemDetail createProblemDetail(OAuth2Error oAuth2Error,
                                              HttpStatusCode httpStatus,
                                              String messageKey,
                                              Map<String, Object> namedArgs, WebRequest request) {
        String errorMessage = messageSource.getMessageWithNamedArgs(
            messageKey, namedArgs, request.getLocale());
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(httpStatus, errorMessage);
        if (StringUtils.hasText(oAuth2Error.getUri())) {
            problem.setType(URI.create(oAuth2Error.getUri()));
        }
        problem.setProperty("error", oAuth2Error.getErrorCode());
        return problem;
    }

    private Map<String, Object> createNamedArgs(String resourceName,
                                                String searchCriteria,
                                                Object searchValue) {
        Map<String, Object> namedArgs = new HashMap<>();
        namedArgs.put("resource", resourceName);
        namedArgs.put("criteria", searchCriteria);
        namedArgs.put("value", searchValue.toString());
        return namedArgs;
    }
}
