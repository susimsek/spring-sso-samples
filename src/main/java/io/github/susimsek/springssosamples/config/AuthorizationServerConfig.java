package io.github.susimsek.springssosamples.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.github.susimsek.springssosamples.exception.security.OAuth2SecurityProblemSupport;
import io.github.susimsek.springssosamples.mapper.OAuth2AuthorizationConsentMapper;
import io.github.susimsek.springssosamples.mapper.OAuth2AuthorizationMapper;
import io.github.susimsek.springssosamples.mapper.RegisteredClientMapper;
import io.github.susimsek.springssosamples.repository.DomainRegisteredClientRepository;
import io.github.susimsek.springssosamples.repository.OAuth2AuthorizationConsentRepository;
import io.github.susimsek.springssosamples.repository.OAuth2AuthorizationRepository;
import io.github.susimsek.springssosamples.repository.OAuth2RegisteredClientRepository;
import io.github.susimsek.springssosamples.security.SecurityProperties;
import io.github.susimsek.springssosamples.service.DomainOAuth2AuthorizationConsentService;
import io.github.susimsek.springssosamples.service.DomainOAuth2AuthorizationService;
import io.github.susimsek.springssosamples.service.DomainOAuth2RegisteredClientService;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final SecurityProperties securityProperties;

    private static final String CONSENT_PAGE_URI = "/oauth2/consent";

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
        HttpSecurity http,
        OAuth2SecurityProblemSupport problemSupport) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .clientAuthentication(clientAuthentication -> clientAuthentication.errorResponseHandler(
                problemSupport::sendClientAuthenticationErrorResponse))
            .oidc(oidc -> oidc
                .clientRegistrationEndpoint(clientRegistrationEndpoint ->
                    clientRegistrationEndpoint.errorResponseHandler(problemSupport))
                .logoutEndpoint(logoutEndpoint -> logoutEndpoint.errorResponseHandler(problemSupport))
                .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint.errorResponseHandler(problemSupport)))
            .tokenEndpoint(tokenEndpoint -> tokenEndpoint.errorResponseHandler(problemSupport))
            .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                .errorResponseHandler(problemSupport::sendAuthorizationEndpointErrorResponse)
                .consentPage(CONSENT_PAGE_URI))
            .tokenIntrospectionEndpoint(tokenIntrospectionEndpoint -> tokenIntrospectionEndpoint
                .errorResponseHandler(problemSupport))
            .tokenRevocationEndpoint(tokenRevocationEndpoint -> tokenRevocationEndpoint
                .errorResponseHandler(problemSupport))
            .deviceAuthorizationEndpoint(deviceAuthorizationEndpoint ->
                deviceAuthorizationEndpoint.errorResponseHandler(problemSupport))
            .deviceVerificationEndpoint(deviceVerificationEndpoint -> deviceVerificationEndpoint
                .errorResponseHandler(problemSupport));

        http
            .exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            )
            .oauth2ResourceServer(oauth2ResourceServer ->
                oauth2ResourceServer.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    public DomainRegisteredClientRepository registeredClientRepository(
        OAuth2RegisteredClientRepository oAuth2RegisteredClientRepository,
        RegisteredClientMapper registeredClientMapper) {
        return new  DomainOAuth2RegisteredClientService(
            oAuth2RegisteredClientRepository, registeredClientMapper);
    }

    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService(
        OAuth2AuthorizationRepository authorizationRepository,
        OAuth2AuthorizationMapper authorizationMapper,
        DomainRegisteredClientRepository registeredClientRepository
    ) {
        return new DomainOAuth2AuthorizationService(
            authorizationRepository, authorizationMapper, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService(
        OAuth2AuthorizationConsentRepository authorizationConsentRepository,
        OAuth2AuthorizationConsentMapper authorizationConsentMapper,
        DomainRegisteredClientRepository registeredClientRepository
    ) {
        return new DomainOAuth2AuthorizationConsentService
            (authorizationConsentRepository, authorizationConsentMapper, registeredClientRepository);
    }

    @Bean
    public KeyPair jwtKeyPair() {
        PublicKey publicKey = RsaKeyConverters.x509().convert(new ByteArrayInputStream(securityProperties.getJwt()
            .getFormattedPublicKey().getBytes(StandardCharsets.UTF_8)));
        PrivateKey privateKey = RsaKeyConverters.pkcs8().convert(new ByteArrayInputStream(securityProperties.getJwt()
            .getFormattedPrivateKey().getBytes(StandardCharsets.UTF_8)));
        return new KeyPair(publicKey, privateKey);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyPair jwtKeyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) jwtKeyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) jwtKeyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }
}
