package io.github.susimsek.springssosamples.config;

import static io.github.susimsek.springssosamples.constant.Constants.SPRING_PROFILE_DEVELOPMENT;
import static io.github.susimsek.springssosamples.constant.Constants.SYSTEM;

import io.github.susimsek.springssosamples.h2.H2ConfigurationHelper;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@Configuration(proxyBeanMethods = false)
@EnableJpaRepositories(basePackages = "io.github.susimsek.springssosamples.repository")
@EnableJpaAuditing(
    dateTimeProviderRef = "dateTimeProvider",
    auditorAwareRef = "springSecurityAuditorAware")
@EnableTransactionManagement
@Slf4j
public class DatabaseConfig {

    @Bean
    public Clock clock() {
        return Clock.systemDefaultZone();
    }

    @Bean
    public AuditorAware<String> springSecurityAuditorAware() {
        return () -> Optional.of(SYSTEM);
    }

    @Bean
    public DateTimeProvider dateTimeProvider(Clock clock) {
        return () -> Optional.of(Instant.now(clock));
    }

    @Bean(initMethod = "start", destroyMethod = "stop")
    @Profile(SPRING_PROFILE_DEVELOPMENT)
    public Object h2TCPServer(Environment environment) throws SQLException {
        String port = getValidPortForH2(environment);
        log.debug("Starting H2 database on port {}", port);
        return H2ConfigurationHelper.createServer(port);
    }

    private String getValidPortForH2(Environment env) {
        int port = Integer.parseInt(env.getProperty("server.port"));
        if (port < 10000) {
            port = 10000 + port;
        } else {
            if (port < 63536) {
                port = port + 2000;
            } else {
                port = port - 2000;
            }
        }
        return String.valueOf(port);
    }
}
