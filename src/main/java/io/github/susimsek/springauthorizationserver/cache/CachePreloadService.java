package io.github.susimsek.springauthorizationserver.cache;

import static io.github.susimsek.springauthorizationserver.config.LocaleConfig.EN;
import static io.github.susimsek.springauthorizationserver.config.LocaleConfig.TR;

import io.github.susimsek.springauthorizationserver.service.MessageService;
import java.util.List;
import java.util.Locale;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CachePreloadService {

    private final MessageService messageService;

    @Async
    public void preloadCache() {
        List<Locale> locales = List.of(TR, EN);
        for (Locale locale : locales) {
            messageService.getMessages(locale.getLanguage());
        }
    }
}
