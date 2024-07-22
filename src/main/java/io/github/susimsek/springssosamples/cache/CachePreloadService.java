package io.github.susimsek.springssosamples.cache;

import io.github.susimsek.springssosamples.service.MessageService;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CachePreloadService {

    private final MessageService messageService;

    @Async
    public void preloadCache() {
        List<String> locales = List.of("tr", "en");
        for (String locale : locales) {
            messageService.getMessages(locale);
        }
    }
}
