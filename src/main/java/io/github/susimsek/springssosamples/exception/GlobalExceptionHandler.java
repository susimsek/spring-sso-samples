package io.github.susimsek.springssosamples.exception;

import io.github.susimsek.springssosamples.i18n.ParameterMessageSource;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
@RequiredArgsConstructor
@Slf4j
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private final ParameterMessageSource messageSource;

    @ExceptionHandler(AuthenticationException.class)
    protected ResponseEntity<Object> handleAuthentication(@NonNull AuthenticationException ex,
                                                          @NonNull WebRequest request) {
        if (ex instanceof OAuth2AuthenticationException oAuth2AuthenticationException) {
            OAuth2Error oAuth2Error = oAuth2AuthenticationException.getError();
            var optionalOAuth2ErrorCode = OAuth2ErrorCode.fromErrorCode(oAuth2Error.getErrorCode());
            if (optionalOAuth2ErrorCode.isPresent()){
                return createProblemDetailResponse(ex, oAuth2Error,
                    optionalOAuth2ErrorCode.get(), new HttpHeaders(), request);
            }
        }
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.INVALID_TOKEN;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, new HttpHeaders(), request);
    }

    @ExceptionHandler(AccessDeniedException.class)
    protected ResponseEntity<Object> handleAccessDenied(@NonNull AccessDeniedException ex,
                                                        @NonNull WebRequest request) {
        OAuth2ErrorCode oAuth2ErrorCode = OAuth2ErrorCode.ACCESS_DENIED;
        return createProblemDetailResponse(ex,  new OAuth2Error(oAuth2ErrorCode.errorCode()),
            oAuth2ErrorCode, new HttpHeaders(), request);
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
        HttpHeaders headers,
        WebRequest request) {
        String errorMessage = messageSource.getMessage(
            oAuth2ErrorCode.messageKey(), null, request.getLocale());
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(oAuth2ErrorCode.httpStatus(), errorMessage);
        if (StringUtils.hasText(oAuth2Error.getUri())) {
            problem.setType(URI.create(oAuth2Error.getUri()));
        }
        problem.setProperty("error", oAuth2Error.getErrorCode());
        return handleExceptionInternal(ex, problem, headers, oAuth2ErrorCode.httpStatus(), request);
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
