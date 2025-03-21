package io.github.susimsek.springauthorizationserver.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.github.susimsek.springauthorizationserver.exception.security.OAuth2SecurityProblemSupport;
import io.github.susimsek.springauthorizationserver.mapper.OAuth2AuthorizationConsentMapper;
import io.github.susimsek.springauthorizationserver.mapper.OAuth2AuthorizationMapper;
import io.github.susimsek.springauthorizationserver.mapper.OAuth2KeyMapper;
import io.github.susimsek.springauthorizationserver.mapper.RegisteredClientMapper;
import io.github.susimsek.springauthorizationserver.repository.DomainRegisteredClientRepository;
import io.github.susimsek.springauthorizationserver.repository.OAuth2AuthorizationConsentRepository;
import io.github.susimsek.springauthorizationserver.repository.OAuth2AuthorizationRepository;
import io.github.susimsek.springauthorizationserver.repository.OAuth2KeyRepository;
import io.github.susimsek.springauthorizationserver.repository.OAuth2RegisteredClientRepository;
import io.github.susimsek.springauthorizationserver.security.oauth2.DomainTokenEncoder;
import io.github.susimsek.springauthorizationserver.security.oauth2.OAuth2KeyJWKSource;
import io.github.susimsek.springauthorizationserver.security.oauth2.OAuth2KeyService;
import io.github.susimsek.springauthorizationserver.security.oauth2.TokenDecoder;
import io.github.susimsek.springauthorizationserver.security.oauth2.TokenEncoder;
import io.github.susimsek.springauthorizationserver.security.oauth2.TokenGenerator;
import io.github.susimsek.springauthorizationserver.security.oauth2.wallet.WalletAuthenticationConverter;
import io.github.susimsek.springauthorizationserver.security.oauth2.wallet.WalletAuthenticationProvider;
import io.github.susimsek.springauthorizationserver.security.oauth2.wallet.WalletSignatureVerifier;
import io.github.susimsek.springauthorizationserver.service.DomainOAuth2AuthorizationConsentService;
import io.github.susimsek.springauthorizationserver.service.DomainOAuth2AuthorizationService;
import io.github.susimsek.springauthorizationserver.service.DomainOAuth2KeyService;
import io.github.susimsek.springauthorizationserver.service.DomainOAuth2RegisteredClientService;
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
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private static final String CONSENT_PAGE_URI = "/oauth2/consent";

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
        HttpSecurity http,
        OAuth2SecurityProblemSupport problemSupport,
        OAuth2AuthorizationService authorizationService,
        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
        WalletSignatureVerifier walletSignatureVerifier) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = context -> {
            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
            JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
            return new OidcUserInfo(principal.getToken().getClaims());
        };

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .clientAuthentication(clientAuthentication -> clientAuthentication.errorResponseHandler(
                problemSupport::sendClientAuthenticationErrorResponse))
            .oidc(oidc -> oidc
                .clientRegistrationEndpoint(clientRegistrationEndpoint ->
                    clientRegistrationEndpoint.errorResponseHandler(problemSupport))
                .logoutEndpoint(logoutEndpoint -> logoutEndpoint.errorResponseHandler(problemSupport))
                .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint.errorResponseHandler(problemSupport)
                    .userInfoMapper(userInfoMapper)))
            .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                .accessTokenRequestConverter(new WalletAuthenticationConverter())
                .authenticationProvider(walletAuthenticationProvider(
                    authorizationService, tokenGenerator, walletSignatureVerifier))
                .errorResponseHandler(problemSupport))
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

    public WalletAuthenticationProvider walletAuthenticationProvider(
        OAuth2AuthorizationService authorizationService,
        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
        WalletSignatureVerifier walletSignatureVerifier) {
        return new WalletAuthenticationProvider(authorizationService, tokenGenerator, walletSignatureVerifier);
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
    public OAuth2KeyService oAuth2KeyService(
        OAuth2KeyRepository authorizationRepository,
        OAuth2KeyMapper authorizationMapper) {
        return new DomainOAuth2KeyService(authorizationRepository, authorizationMapper);
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public JWKSource<SecurityContext> jwkSource(OAuth2KeyService auth2KeyService) {
        return new OAuth2KeyJWKSource(auth2KeyService);
    }

    @Bean
    public TokenEncoder tokenEncoder(JWKSource<SecurityContext> jwkSource) {
        return new DomainTokenEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(
        OAuth2KeyService oAuth2KeyService,
        JWKSource<SecurityContext> jwkSource) {
        Set<JWSAlgorithm> jwsAlgs = new HashSet<>();
        jwsAlgs.addAll(JWSAlgorithm.Family.RSA);
        jwsAlgs.addAll(JWSAlgorithm.Family.EC);
        jwsAlgs.addAll(JWSAlgorithm.Family.HMAC_SHA);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(jwsAlgs, jwkSource);
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
        });
        return new TokenDecoder(oAuth2KeyService, jwtProcessor);
    }

    @Bean
    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer() {
        return context -> {
        };
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(TokenEncoder tokenEncoder,
                                                  OAuth2KeyService oAuth2KeyService,
                                                  OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer) {
        var tokenGenerator = new TokenGenerator(tokenEncoder, oAuth2KeyService);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer);
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(
            tokenGenerator, accessTokenGenerator, refreshTokenGenerator);
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
