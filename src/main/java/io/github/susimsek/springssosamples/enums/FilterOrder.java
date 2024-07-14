package io.github.susimsek.springssosamples.enums;

import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;
import static org.springframework.core.Ordered.LOWEST_PRECEDENCE;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;


@Getter
@Accessors(fluent = true)
@RequiredArgsConstructor
public enum FilterOrder {
    LOGGING(LOWEST_PRECEDENCE);

    private final int order;
}
