package io.github.susimsek.springauthorizationserver.config;

import io.github.susimsek.springauthorizationserver.client.RestClientProperties;
import io.github.susimsek.springauthorizationserver.logging.wrapper.HttpLoggingWrapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.web.client.RestClientBuilderConfigurer;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.ClientHttpRequestFactories;
import org.springframework.boot.web.client.ClientHttpRequestFactorySettings;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.web.client.RestClient;

@Configuration
@EnableConfigurationProperties(RestClientProperties.class)
@RequiredArgsConstructor
public class RestClientConfig {

    private final RestClientProperties restClientProperties;

    @Bean
    @Scope("prototype")
    RestClient.Builder restClientBuilder(
        RestClientBuilderConfigurer restClientBuilderConfigurer,
        ObjectProvider<HttpLoggingWrapper> httpLoggingWrapperProvider) {
        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.DEFAULTS
            .withConnectTimeout(restClientProperties.getConnectTimeout())
            .withReadTimeout(restClientProperties.getReadTimeout());
        RestClient.Builder builder = RestClient.builder()
            .requestFactory(ClientHttpRequestFactories.get(settings));
        HttpLoggingWrapper httpLoggingWrapper = httpLoggingWrapperProvider.getIfAvailable();
        if (httpLoggingWrapper != null) {
            builder = builder.requestInterceptor(httpLoggingWrapper.createRestClientInterceptor());
        }
        return restClientBuilderConfigurer.configure(builder);
    }
}
