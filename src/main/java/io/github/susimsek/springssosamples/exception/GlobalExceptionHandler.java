package io.github.susimsek.springssosamples.exception;

import io.github.susimsek.springssosamples.i18n.ParameterMessageSource;
import jakarta.validation.ConstraintViolationException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.TypeMismatchException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.MEDIA_TYPE_NOT_ACCEPTABLE;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(
        @NonNull HttpMediaTypeNotSupportedException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.MEDIA_TYPE_NOT_SUPPORTED;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(
        @NonNull HttpRequestMethodNotSupportedException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.REQUEST_METHOD_NOT_SUPPORTED;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(
        @NonNull HttpMessageNotReadableException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.MESSAGE_NOT_READABLE;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleTypeMismatch(
        @NonNull TypeMismatchException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.TYPE_MISMATCH;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(
        @NonNull MissingServletRequestParameterException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        Map<String, Object> namedArgs = Map.of("paramName", ex.getParameterName());
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.MISSING_PARAMETER;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, namedArgs, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestPart(
        @NonNull MissingServletRequestPartException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        Map<String, Object> namedArgs = Map.of("partName", ex.getRequestPartName());
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.MISSING_PART;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, namedArgs, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleServletRequestBindingException(
        @NonNull ServletRequestBindingException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.REQUEST_BINDING_ERROR;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, new HttpHeaders(), request);
    }

    @ExceptionHandler(MultipartException.class)
    protected ResponseEntity<Object> handleMultipartException(@NonNull MultipartException ex,
                                                              @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.MULTIPART_ERROR;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, new HttpHeaders(), request);
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

        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.VALIDATION_ERROR;
        ProblemDetail problem = createProblemDetail(new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, request);
        problem.setProperty(ErrorConstants.PROBLEM_VIOLATION_KEY, violations);
        return handleExceptionInternal(ex, problem, headers, oAuth2ErrorCode.httpStatus(), request);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    protected ResponseEntity<Object> handleConstraintViolationException(
        @NonNull ConstraintViolationException ex,
        @NonNull WebRequest request) {
        List<Violation> violations = ex.getConstraintViolations().stream().map(Violation::new).toList();

        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.VALIDATION_ERROR;
        ProblemDetail problem = createProblemDetail(new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, request);
        problem.setProperty(ErrorConstants.PROBLEM_VIOLATION_KEY, violations);
        return handleExceptionInternal(ex, problem, new HttpHeaders(), oAuth2ErrorCode.httpStatus(), request);
    }

    @ExceptionHandler(AuthenticationException.class)
    protected ResponseEntity<Object> handleAuthentication(@NonNull AuthenticationException ex,
                                                          @NonNull WebRequest request) {
        if (ex instanceof OAuth2AuthenticationException oAuth2AuthenticationException) {
            OAuth2Error oAuth2Error = oAuth2AuthenticationException.getError();
            var optionalOAuth2ErrorCode = OAuth2ErrorCode.fromErrorCode(oAuth2Error.getErrorCode());
            if (optionalOAuth2ErrorCode.isPresent()){
                return createProblemDetailResponse(ex, oAuth2Error,
                    optionalOAuth2ErrorCode.get(), null, new HttpHeaders(), request);
            }
        }
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.INVALID_TOKEN;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, new HttpHeaders(), request);
    }

    @ExceptionHandler(AccessDeniedException.class)
    protected ResponseEntity<Object> handleAccessDenied(@NonNull AccessDeniedException ex,
                                                        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.ACCESS_DENIED;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleNoHandlerFoundException(
        @NonNull NoHandlerFoundException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.NO_HANDLER_FOUND;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, new HttpHeaders(), request);
    }

    @ExceptionHandler(UnsupportedOperationException.class)
    public ResponseEntity<Object> handleUnsupportedOperationException(
        @NonNull UnsupportedOperationException ex,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.UNSUPPORTED_OPERATION;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, new HttpHeaders(), request);
    }

    @ExceptionHandler(SocketTimeoutException.class)
    public ResponseEntity<Object> handleSocketTimeoutException(@NonNull SocketTimeoutException ex,
                                                               @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.GATEWAY_TIMEOUT;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, new HttpHeaders(), request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleAllExceptions(
        @NonNull Exception ex,
        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.SERVER_ERROR;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, null, new HttpHeaders(), request);
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
        OAuth2ErrorCode oAuth2ErrorCode,
        Map<String, Object> namedArgs,
        HttpHeaders headers,
        WebRequest request) {
        ProblemDetail problem = createProblemDetail(oAuth2Error, oAuth2ErrorCode, namedArgs, request);
        return handleExceptionInternal(ex, problem, headers, oAuth2ErrorCode.httpStatus(), request);
    }

    private ProblemDetail createProblemDetail(OAuth2Error oAuth2Error, OAuth2ErrorCode oAuth2ErrorCode,
                                           Map<String, Object> namedArgs, WebRequest request) {
        String errorMessage = messageSource.getMessageWithNamedArgs(
            oAuth2ErrorCode.messageKey(), namedArgs, request.getLocale());
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(oAuth2ErrorCode.httpStatus(), errorMessage);
        if (StringUtils.hasText(oAuth2Error.getUri())) {
            problem.setType(URI.create(oAuth2Error.getUri()));
        }
        problem.setProperty("error", oAuth2Error.getErrorCode());
        return problem;
    }
}
