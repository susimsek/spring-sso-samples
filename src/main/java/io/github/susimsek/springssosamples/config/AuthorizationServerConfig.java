package io.github.susimsek.springssosamples.config;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.github.susimsek.springssosamples.exception.security.OAuth2SecurityProblemSupport;
import io.github.susimsek.springssosamples.mapper.OAuth2AuthorizationConsentMapper;
import io.github.susimsek.springssosamples.mapper.OAuth2AuthorizationMapper;
import io.github.susimsek.springssosamples.mapper.RegisteredClientMapper;
import io.github.susimsek.springssosamples.repository.DomainRegisteredClientRepository;
import io.github.susimsek.springssosamples.repository.OAuth2AuthorizationConsentRepository;
import io.github.susimsek.springssosamples.repository.OAuth2AuthorizationRepository;
import io.github.susimsek.springssosamples.repository.OAuth2RegisteredClientRepository;
import io.github.susimsek.springssosamples.security.JweToken;
import io.github.susimsek.springssosamples.security.SecurityProperties;
import io.github.susimsek.springssosamples.security.oauth2.JweDecoder;
import io.github.susimsek.springssosamples.security.oauth2.DomainTokenEncoder;
import io.github.susimsek.springssosamples.security.oauth2.JweGenerator;
import io.github.susimsek.springssosamples.security.oauth2.TokenEncoder;
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
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

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
                    createRequestMatcher()
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
        return new DomainOAuth2RegisteredClientService(
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
    public KeyPair jweKeyPair() {
        var jweProperties = securityProperties.getJwe();
        PublicKey publicKey = RsaKeyConverters.x509().convert(new ByteArrayInputStream(jweProperties
            .getFormattedPublicKey().getBytes(StandardCharsets.UTF_8)));
        PrivateKey privateKey = RsaKeyConverters.pkcs8().convert(new ByteArrayInputStream(jweProperties
            .getFormattedPrivateKey().getBytes(StandardCharsets.UTF_8)));
        return new KeyPair(publicKey, privateKey);
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public JWKSource<SecurityContext> jwkSource(KeyPair jwtKeyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) jwtKeyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) jwtKeyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID("430b5ff6-522c-4b49-b8a7-de101d14df6e")
            .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public TokenEncoder tokenEncoder(KeyPair jweKeyPair, JWKSource<SecurityContext> jwkSource)  {
        return new DomainTokenEncoder(jweKeyPair, jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(KeyPair jweKeyPair, JWKSource<SecurityContext> jwkSource) {
        var jweProperties = securityProperties.getJwe();
        Set<JWSAlgorithm> jwsAlgs = new HashSet<>();
        jwsAlgs.addAll(JWSAlgorithm.Family.RSA);
        jwsAlgs.addAll(JWSAlgorithm.Family.EC);
        jwsAlgs.addAll(JWSAlgorithm.Family.HMAC_SHA);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(jwsAlgs, jwkSource);
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
        });
        if (Boolean.TRUE.equals(jweProperties.getEnabled())) {
            return new JweDecoder(jweKeyPair, jwtProcessor);
        }
        return new NimbusJwtDecoder(jwtProcessor);
    }

    @Bean
    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer() {
        return context -> {};
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(TokenEncoder tokenEncoder,
                                                  OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer) {
        var jwtGenerator = new JweGenerator(tokenEncoder);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer);
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(
            jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    private static RequestMatcher createRequestMatcher() {
        MediaTypeRequestMatcher requestMatcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
        requestMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
        return requestMatcher;
    }
}
