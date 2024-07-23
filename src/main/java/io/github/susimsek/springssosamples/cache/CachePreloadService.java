package io.github.susimsek.springssosamples.cache;

import static io.github.susimsek.springssosamples.config.LocaleConfig.EN;
import static io.github.susimsek.springssosamples.config.LocaleConfig.TR;

import io.github.susimsek.springssosamples.service.MessageService;
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
