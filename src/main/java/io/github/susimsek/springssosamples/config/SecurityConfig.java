package io.github.susimsek.springssosamples.config;

import static org.springframework.security.config.Customizer.withDefaults;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.github.susimsek.springssosamples.mapper.OAuth2AuthorizationConsentMapper;
import io.github.susimsek.springssosamples.mapper.OAuth2AuthorizationMapper;
import io.github.susimsek.springssosamples.mapper.RegisteredClientMapper;
import io.github.susimsek.springssosamples.mapper.UserMapper;
import io.github.susimsek.springssosamples.repository.DomainRegisteredClientRepository;
import io.github.susimsek.springssosamples.repository.OAuth2AuthorizationConsentRepository;
import io.github.susimsek.springssosamples.repository.OAuth2AuthorizationRepository;
import io.github.susimsek.springssosamples.repository.OAuth2RegisteredClientRepository;
import io.github.susimsek.springssosamples.repository.UserRepository;
import io.github.susimsek.springssosamples.security.SecurityProperties;
import io.github.susimsek.springssosamples.service.DomainOAuth2AuthorizationConsentService;
import io.github.susimsek.springssosamples.service.DomainOAuth2AuthorizationService;
import io.github.susimsek.springssosamples.service.DomainOAuth2RegisteredClientService;
import io.github.susimsek.springssosamples.service.DomainUserDetailsService;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
@EnableConfigurationProperties(SecurityProperties.class)
@RequiredArgsConstructor
public class SecurityConfig {

    private final SecurityProperties securityProperties;

    private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
        HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .authorizationEndpoint(authorizationEndpoint ->
                authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
            .oidc(Customizer.withDefaults());

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
    public SecurityFilterChain defaultSecurityFilterChain(
        HttpSecurity http,
        RequestMatcherConfig requestMatcherConfig) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .cors(withDefaults())
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(securityProperties.getContentSecurityPolicy()))
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                .referrerPolicy(
                    referrer -> referrer.policy(
                        ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                ))
            .authorizeHttpRequests(authz ->
                authz
                    .requestMatchers(requestMatcherConfig.staticResources()).permitAll()
                    .requestMatchers(requestMatcherConfig.swaggerPaths()).permitAll()
                    .requestMatchers(requestMatcherConfig.actuatorPaths()).permitAll()
                    .anyRequest().authenticated())
            .formLogin(formLogin -> formLogin.loginPage("/login")
                .failureUrl("/login?error=true")
                .permitAll())
            .logout(logout -> logout
                .logoutSuccessUrl("/login?logout=true")
            );
        return http.build();
    }

    @Bean
    MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
        return new MvcRequestMatcher.Builder(introspector);
    }

    @Bean
    RequestMatcherConfig requestMatchersConfig(MvcRequestMatcher.Builder mvc) {
        return new RequestMatcherConfig(mvc);
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
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository,
                                                 UserMapper userMapper) {
        return new DomainUserDetailsService(userRepository, userMapper);
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
