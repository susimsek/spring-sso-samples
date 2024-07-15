package io.github.susimsek.springssosamples.filter;

import io.github.susimsek.springssosamples.enums.FilterOrder;
import io.github.susimsek.springssosamples.logging.enums.Source;
import io.github.susimsek.springssosamples.logging.handler.HttpLoggingHandler;
import io.github.susimsek.springssosamples.logging.handler.LoggingHandler;
import io.github.susimsek.springssosamples.utils.HttpHeadersUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.lang.NonNull;
import org.springframework.util.StopWatch;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

@Slf4j
@RequiredArgsConstructor
public class LoggingFilter extends OncePerRequestFilter  implements Ordered {

    private final LoggingHandler loggingHandler;

    @Setter
    private int order = FilterOrder.LOGGING.order();

    @Override
    public int getOrder() {
        return order;
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        return loggingHandler.shouldNotLog(request);
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        ContentCachingRequestWrapper wrappedRequest = wrapRequest(request);
        ContentCachingResponseWrapper wrappedResponse = wrapResponse(response);

        StopWatch stopWatch = new StopWatch();
        stopWatch.start();

        filterChain.doFilter(wrappedRequest, wrappedResponse);

        stopWatch.stop();
        long duration = stopWatch.getTotalTimeMillis();

        logRequestAndResponse(wrappedRequest, wrappedResponse, duration);
        wrappedResponse.copyBodyToResponse();
    }

    private void logRequestAndResponse(ContentCachingRequestWrapper request,
                                       ContentCachingResponseWrapper response,
                                       long duration) {
        try {
            URI uri = new URI(request.getRequestURL().toString());
            HttpHeaders requestHeaders = HttpHeadersUtils.convertToHttpHeaders(request);
            HttpHeaders responseHeaders = HttpHeadersUtils.convertToHttpHeaders(response);

            loggingHandler.logRequest(
                HttpMethod.valueOf(request.getMethod()),
                uri,
                requestHeaders,
                request.getContentAsByteArray(),
                Source.SERVER
            );
            loggingHandler.logResponse(
                HttpMethod.valueOf(request.getMethod()),
                uri,
                response.getStatus(),
                responseHeaders,
                response.getContentAsByteArray(),
                Source.SERVER,
                duration
            );
        } catch (URISyntaxException e) {
            log.error("Invalid URI Syntax for request: {}", request.getRequestURL(), e);
        }
    }

    private static ContentCachingRequestWrapper wrapRequest(HttpServletRequest request) {
        if (request instanceof ContentCachingRequestWrapper wrapper) {
            return wrapper;
        } else {
            return new ContentCachingRequestWrapper(request);
        }
    }

    private static ContentCachingResponseWrapper wrapResponse(HttpServletResponse response) {
        if (response instanceof ContentCachingResponseWrapper wrapper) {
            return wrapper;
        } else {
            return new ContentCachingResponseWrapper(response);
        }
    }
}
