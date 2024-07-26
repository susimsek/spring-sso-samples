package io.github.susimsek.springauthorizationserver.enums;

import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;


@Getter
@Accessors(fluent = true)
@RequiredArgsConstructor
public enum FilterOrder {
    LOGGING(HIGHEST_PRECEDENCE + 1),
    XSS(HIGHEST_PRECEDENCE + 2);

    private final int order;
}
