package io.github.susimsek.springauthorizationserver.service;

import io.github.susimsek.springauthorizationserver.entity.OAuth2AuthorizationEntity;
import io.github.susimsek.springauthorizationserver.mapper.OAuth2AuthorizationMapper;
import io.github.susimsek.springauthorizationserver.repository.DomainRegisteredClientRepository;
import io.github.susimsek.springauthorizationserver.repository.OAuth2AuthorizationRepository;
import io.github.susimsek.springauthorizationserver.specification.OAuth2AuthorizationSpecification;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

@RequiredArgsConstructor
public class DomainOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationRepository authorizationRepository;
    private final OAuth2AuthorizationMapper authorizationMapper;
    private final DomainRegisteredClientRepository registeredClientRepository;

    @Override
    @Transactional
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        Optional<OAuth2AuthorizationEntity> existingAuthorization = authorizationRepository.findById(authorization.getId());
        if (existingAuthorization.isPresent()) {
            updateAuthorization(authorization, existingAuthorization.get());
        } else {
            insertAuthorization(authorization);
        }
    }

    private void updateAuthorization(OAuth2Authorization authorization, OAuth2AuthorizationEntity existingAuthorization) {
        OAuth2AuthorizationEntity entity = authorizationMapper.toEntity(authorization);
        entity.setId(existingAuthorization.getId());
        authorizationRepository.save(entity);
    }

    private void insertAuthorization(OAuth2Authorization authorization) {
        OAuth2AuthorizationEntity entity = authorizationMapper.toEntity(authorization);
        authorizationRepository.save(entity);
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return authorizationRepository.findById(id)
            .map(entity -> {
                RegisteredClient registeredClient = registeredClientRepository.findByIdOrThrow(entity.getRegisteredClientId());
                return authorizationMapper.toModel(entity, registeredClient);
            })
            .orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        Specification<OAuth2AuthorizationEntity> spec = OAuth2AuthorizationSpecification.hasToken(token, tokenType != null ? tokenType.getValue() : null);
        return authorizationRepository.findOne(spec)
            .map(entity -> {
                RegisteredClient registeredClient = registeredClientRepository.findByIdOrThrow(entity.getRegisteredClientId());
                return authorizationMapper.toModel(entity, registeredClient);
            })
            .orElse(null);
    }

    @Override
    @Transactional
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        authorizationRepository.deleteById(authorization.getId());
    }
}
