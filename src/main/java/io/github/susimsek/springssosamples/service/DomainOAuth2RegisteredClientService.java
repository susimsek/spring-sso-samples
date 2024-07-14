package io.github.susimsek.springssosamples.service;

import io.github.susimsek.springssosamples.entity.OAuth2RegisteredClientEntity;
import io.github.susimsek.springssosamples.mapper.RegisteredClientMapper;
import io.github.susimsek.springssosamples.repository.DomainRegisteredClientRepository;
import io.github.susimsek.springssosamples.repository.OAuth2RegisteredClientRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

@Slf4j
@RequiredArgsConstructor
public class DomainOAuth2RegisteredClientService implements DomainRegisteredClientRepository {

    private final OAuth2RegisteredClientRepository registeredClientRepository;
    private final RegisteredClientMapper registeredClientMapper;

    @Override
    @Transactional
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        Optional<OAuth2RegisteredClientEntity> existingRegisteredClient = registeredClientRepository.findByClientId(registeredClient.getClientId());
        if (existingRegisteredClient.isPresent()) {
            updateRegisteredClient(registeredClient, existingRegisteredClient.get());
        } else {
            insertRegisteredClient(registeredClient);
        }
    }

    private void assertUniqueIdentifiers(RegisteredClient registeredClient) {
        Integer count = this.registeredClientRepository.countByClientId(registeredClient.getClientId());
        if (count != null && count > 0) {
            throw new IllegalArgumentException("Registered client must be unique. "
                + "Found duplicate client identifier: " + registeredClient.getClientId());
        }
        if (StringUtils.hasText(registeredClient.getClientSecret())) {
            count = this.registeredClientRepository.countByClientSecret(registeredClient.getClientSecret());
            if (count != null && count > 0) {
                throw new IllegalArgumentException("Registered client must be unique. "
                    + "Found duplicate client secret for identifier: " + registeredClient.getId());
            }
        }
    }

    private void insertRegisteredClient(RegisteredClient registeredClient) {
        assertUniqueIdentifiers(registeredClient);
        OAuth2RegisteredClientEntity client = registeredClientMapper.toEntity(registeredClient);
        registeredClientRepository.save(client);
    }

    private void updateRegisteredClient(RegisteredClient registeredClient, OAuth2RegisteredClientEntity existingClient) {
        OAuth2RegisteredClientEntity client = registeredClientMapper.toEntity(registeredClient);
        client.setId(existingClient.getId());
        registeredClientRepository.save(client);
    }

    @Override
    @Transactional(readOnly = true)
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return registeredClientRepository.findById(id)
            .map(registeredClientMapper::toDto)
            .orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        return registeredClientRepository.findByClientId(clientId)
            .map(registeredClientMapper::toDto)
            .orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public RegisteredClient findByIdOrThrow(String id) {
        Assert.hasText(id, "id cannot be empty");
        return registeredClientRepository.findById(id)
            .map(registeredClientMapper::toDto)
            .orElseThrow(() -> new DataRetrievalFailureException("The RegisteredClient with id '"
                + id + "' was not found in the RegisteredClientRepository."));
    }
}
