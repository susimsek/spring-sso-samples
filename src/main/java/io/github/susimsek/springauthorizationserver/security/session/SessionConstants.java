package io.github.susimsek.springauthorizationserver.security.session;

import java.time.Duration;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SessionConstants {
    public static final Duration DEFAULT_MAX_INACTIVE_INTERVAL = Duration.ofSeconds(1800L);
    public static final String DEFAULT_CLEANUP_CRON = "0 * * * * *";
}
