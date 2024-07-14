package io.github.susimsek.springssosamples.logging.wrapper;


import io.github.susimsek.springssosamples.logging.handler.LoggingHandler;
import io.github.susimsek.springssosamples.interceptor.RestClientLoggingInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.client.ClientHttpRequestInterceptor;

@RequiredArgsConstructor
public class HttpLoggingWrapper {

    private final LoggingHandler loggingHandler;

    public ClientHttpRequestInterceptor createRestClientInterceptor() {
        return new RestClientLoggingInterceptor(loggingHandler);
    }
}
