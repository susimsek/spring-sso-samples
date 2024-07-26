package io.github.susimsek.springauthorizationserver.utils;

import io.github.susimsek.springauthorizationserver.security.xss.XssRequestWrapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import lombok.experimental.UtilityClass;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

@UtilityClass
public class HttpServletWrapperUtils {

    public static ContentCachingRequestWrapper wrapRequest(HttpServletRequest request) {
        if (request instanceof ContentCachingRequestWrapper wrapper) {
            return wrapper;
        } else {
            return new ContentCachingRequestWrapper(request);
        }
    }

    public static XssRequestWrapper wrapRequest(HttpServletRequest request,
                                                List<String> nonSanitizedHeaders) {
        if (request instanceof XssRequestWrapper wrapper) {
            return wrapper;
        } else {
            return new XssRequestWrapper(request, nonSanitizedHeaders);
        }
    }

    public static ContentCachingResponseWrapper wrapResponse(HttpServletResponse response) {
        if (response instanceof ContentCachingResponseWrapper wrapper) {
            return wrapper;
        } else {
            return new ContentCachingResponseWrapper(response);
        }
    }
}
