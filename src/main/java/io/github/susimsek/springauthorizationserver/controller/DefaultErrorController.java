package io.github.susimsek.springauthorizationserver.controller;

import io.github.susimsek.springauthorizationserver.exception.OAuth2ErrorCode;
import io.github.susimsek.springauthorizationserver.i18n.ParameterMessageSource;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Locale;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequiredArgsConstructor
public class DefaultErrorController implements ErrorController {

    private final ParameterMessageSource messageSource;

    @RequestMapping("/error")
    public String handleError(Model model, Locale locale, HttpServletRequest request) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        String errorTitle = messageSource.getMessage("error.title", null, locale);
        String errorMessage;
        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());

            errorMessage = switch (HttpStatus.valueOf(statusCode)) {
                case NOT_FOUND -> messageSource.getMessage(OAuth2ErrorCode.NOT_FOUND.messageKey(), null, locale);
                case FORBIDDEN -> messageSource.getMessage(OAuth2ErrorCode.ACCESS_DENIED.messageKey(), null, locale);
                default -> messageSource.getMessage(OAuth2ErrorCode.SERVER_ERROR.messageKey(), null, locale);
            };
        } else {
            errorMessage = getErrorMessage(request);
            if (errorMessage.startsWith("[access_denied]")) {
                errorMessage = messageSource.getMessage(OAuth2ErrorCode.ACCESS_DENIED.messageKey(), null, locale);
            } else {
                errorMessage = messageSource.getMessage(OAuth2ErrorCode.SERVER_ERROR.messageKey(), null, locale);
            }
        }
        model.addAttribute("errorTitle", errorTitle);
        model.addAttribute("errorMessage", errorMessage);
        return "error";
    }

    private String getErrorMessage(HttpServletRequest request) {
        String errorMessage = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
        return StringUtils.hasText(errorMessage) ? errorMessage : "";
    }
}
