package io.github.susimsek.springauthorizationserver.config;

import static io.github.susimsek.springauthorizationserver.constant.Constants.SPRING_PROFILE_DEVELOPMENT;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

import io.github.susimsek.springauthorizationserver.enums.FilterOrder;
import io.github.susimsek.springauthorizationserver.filter.XssFilter;
import io.github.susimsek.springauthorizationserver.mapper.UserMapper;
import io.github.susimsek.springauthorizationserver.repository.UserRepository;
import io.github.susimsek.springauthorizationserver.security.SecurityProperties;
import io.github.susimsek.springauthorizationserver.service.DomainUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
@EnableConfigurationProperties(SecurityProperties.class)
@RequiredArgsConstructor
public class SecurityConfig {

    private final SecurityProperties securityProperties;
    private final Environment env;

    private static final String LOGIN_PAGE_URI = "/login";

    @Bean
    @Order(org.springframework.boot.autoconfigure.security.SecurityProperties.BASIC_AUTH_ORDER)
    public SecurityFilterChain defaultSecurityFilterChain(
        HttpSecurity http,
        RequestMatcherConfig requestMatcherConfig,
        XssFilter xssFilter,
        MvcRequestMatcher.Builder mvc) throws Exception {
        if (env.acceptsProfiles(Profiles.of(SPRING_PROFILE_DEVELOPMENT))) {
            http.authorizeHttpRequests(authz -> authz.requestMatchers(antMatcher("/h2-console/**")).permitAll());
        }
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
                    .requestMatchers(mvc.pattern(LOGIN_PAGE_URI)).permitAll()
                    .anyRequest().authenticated())
            .formLogin(formLogin -> formLogin.loginPage(LOGIN_PAGE_URI)
                .failureUrl(LOGIN_PAGE_URI + "?error=true"))
            .logout(logout -> logout
                .logoutSuccessUrl(LOGIN_PAGE_URI + "?logout=true")
            )
            .addFilterAfter(xssFilter, BearerTokenAuthenticationFilter.class);
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
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository,
                                                 UserMapper userMapper) {
        return new DomainUserDetailsService(userRepository, userMapper);
    }

    @Bean
    public XssFilter xssFilter(
        RequestMatcherConfig requestMatcherConfig) {
        return XssFilter.builder()
            .order(FilterOrder.XSS.order())
            .requestMatchers(requestMatcherConfig.staticResources()).permitAll()
            .requestMatchers(requestMatcherConfig.swaggerPaths()).permitAll()
            .requestMatchers(requestMatcherConfig.actuatorPaths()).permitAll()
            .anyRequest().sanitized()
            .nonSanitizedHeaders(
                HttpHeaders.CONTENT_ENCODING, HttpHeaders.CACHE_CONTROL,
                HttpHeaders.CONTENT_TYPE, HttpHeaders.CONTENT_LENGTH, HttpHeaders.AUTHORIZATION,
                HttpHeaders.COOKIE, HttpHeaders.HOST, HttpHeaders.USER_AGENT,
                HttpHeaders.REFERER, HttpHeaders.ACCEPT,
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "sec-fetch-site",
                "sec-fetch-mode",
                "sec-fetch-user",
                "sec-fetch-dest")
            .build();
    }
}
