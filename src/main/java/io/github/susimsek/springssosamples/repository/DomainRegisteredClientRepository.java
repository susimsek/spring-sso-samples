package io.github.susimsek.springssosamples.repository;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

public interface DomainRegisteredClientRepository  extends RegisteredClientRepository {
    RegisteredClient findByIdOrThrow(String id);
}
