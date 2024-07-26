package io.github.susimsek.springauthorizationserver.i18n;


import io.github.susimsek.springauthorizationserver.service.MessageService;

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
