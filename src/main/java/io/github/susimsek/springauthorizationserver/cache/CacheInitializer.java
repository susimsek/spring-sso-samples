package io.github.susimsek.springauthorizationserver.cache;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CacheInitializer {

    private final CachePreloadService cacheWarmUpService;

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationEvent() {
        cacheWarmUpService.preloadCache();
    }
}
