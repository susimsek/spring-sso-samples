package io.github.susimsek.springssosamples.exception.security;

import io.github.susimsek.springssosamples.exception.OAuth2ErrorCode;
import io.github.susimsek.springssosamples.i18n.ParameterMessageSource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

@Component
public class OAuth2AuthorizationProblemSupport implements AuthenticationFailureHandler {

    Logger logger = LoggerFactory.getLogger(OAuth2AuthorizationProblemSupport.class);
    private final RedirectStrategy redirectStrategy;
    private final ParameterMessageSource messageSource;

    public OAuth2AuthorizationProblemSupport(ParameterMessageSource messageSource) {
        this.messageSource = messageSource;
        this.redirectStrategy =  new DefaultRedirectStrategy();
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException ex) throws IOException {
        sendErrorResponse(request, response, ex);
    }


    private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws
        IOException {
        OAuth2AuthorizationCodeRequestAuthenticationException authorizationCodeRequestAuthenticationException = (OAuth2AuthorizationCodeRequestAuthenticationException)exception;
        OAuth2Error error = authorizationCodeRequestAuthenticationException.getError();
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = authorizationCodeRequestAuthenticationException.getAuthorizationCodeRequestAuthentication();
        if (authorizationCodeRequestAuthentication != null && StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Redirecting to client with error");
            }

            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(
                authorizationCodeRequestAuthentication.getRedirectUri()).queryParam("error", new Object[]{error.getErrorCode()});
            String description = error.getDescription();
            if (StringUtils.hasText(error.getDescription())) {
                var optionalOAuth2ErrorCode = OAuth2ErrorCode.fromErrorCode(error.getErrorCode());
                if (optionalOAuth2ErrorCode.isPresent()) {
                    OAuth2ErrorCode oAuth2ErrorCode = optionalOAuth2ErrorCode.get();
                    description = messageSource.getMessageWithNamedArgs(
                        oAuth2ErrorCode.messageKey(), null, request.getLocale());
                }
                uriBuilder.queryParam("error_description",
                    UriUtils.encode(description, StandardCharsets.UTF_8));
            }

            if (StringUtils.hasText(error.getUri())) {
                uriBuilder.queryParam("error_uri", UriUtils.encode(error.getUri(), StandardCharsets.UTF_8));
            }

            if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
                uriBuilder.queryParam("state",
                    UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
            }

            String redirectUri = uriBuilder.build(true).toUriString();
            this.redirectStrategy.sendRedirect(request, response, redirectUri);
        } else {
            response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
        }
    }
}
