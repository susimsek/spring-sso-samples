package io.github.susimsek.springssosamples.i18n;


import io.github.susimsek.springssosamples.service.MessageService;

public class SimpleParameterMessageSource extends DatabaseMessageSource {
    /**
     * Constructs a new DatabaseMessageSource.
     *
     * @param messageService the service to fetch messages from the database
     */
    public SimpleParameterMessageSource(MessageService messageService) {
        super(messageService);
    }
}
