package io.github.susimsek.springauthorizationserver.config;

import static io.github.susimsek.springauthorizationserver.security.session.SessionConstants.DEFAULT_CLEANUP_CRON;
import static io.github.susimsek.springauthorizationserver.security.session.SessionConstants.DEFAULT_MAX_INACTIVE_INTERVAL;

import io.github.susimsek.springauthorizationserver.repository.UserSessionAttributeRepository;
import io.github.susimsek.springauthorizationserver.repository.UserSessionRepository;
import io.github.susimsek.springauthorizationserver.security.session.JsonConversionUtils;
import io.github.susimsek.springauthorizationserver.service.DomainSessionService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.session.UuidSessionIdGenerator;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;

@Configuration(proxyBeanMethods = false)
@EnableJdbcHttpSession
public class SessionConfig {

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public DomainSessionService sessionRepository(UserSessionRepository springSessionRepository,
                                                  UserSessionAttributeRepository springSessionAttributeRepository,
                                                  JsonConversionUtils jsonConversionUtils) {
        DomainSessionService sessionService = new DomainSessionService(
            springSessionRepository, springSessionAttributeRepository, jsonConversionUtils);
        sessionService.setDefaultMaxInactiveInterval(DEFAULT_MAX_INACTIVE_INTERVAL);
        sessionService.setCleanupCron(DEFAULT_CLEANUP_CRON);
        sessionService.setSessionIdGenerator(UuidSessionIdGenerator.getInstance());
        return sessionService;
    }
}
