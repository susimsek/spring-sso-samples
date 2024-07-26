package io.github.susimsek.springauthorizationserver.service;

import io.github.susimsek.springauthorizationserver.entity.OAuth2KeyEntity;
import io.github.susimsek.springauthorizationserver.mapper.OAuth2KeyMapper;
import io.github.susimsek.springauthorizationserver.repository.OAuth2KeyRepository;
import io.github.susimsek.springauthorizationserver.security.oauth2.OAuth2Key;
import io.github.susimsek.springauthorizationserver.security.oauth2.OAuth2KeyService;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

@RequiredArgsConstructor
public class DomainOAuth2KeyService implements OAuth2KeyService {

    private final OAuth2KeyRepository authorizationRepository;
    private final OAuth2KeyMapper authorizationMapper;

    @Override
    @Transactional
    public void save(OAuth2Key key) {
        Assert.notNull(key, "key cannot be null");
        Optional<OAuth2KeyEntity> existingKey = authorizationRepository.findById(key.getId());
        if (existingKey.isPresent()) {
            updateKey(key, existingKey.get());
        } else {
            insertKey(key);
        }
    }

    private void updateKey(OAuth2Key key, OAuth2KeyEntity existingKey) {
        OAuth2KeyEntity entity = authorizationMapper.toEntity(key);
        entity.setId(existingKey.getId());
        authorizationRepository.save(entity);
    }

    private void insertKey(OAuth2Key key) {
        OAuth2KeyEntity entity = authorizationMapper.toEntity(key);
        authorizationRepository.save(entity);
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2Key findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return authorizationRepository.findById(id)
            .map(authorizationMapper::toModel)
            .orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2Key findByKid(String kid) {
        Assert.hasText(kid, "kid cannot be empty");
        return authorizationRepository.findById(kid)
            .map(authorizationMapper::toModel)
            .orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2Key findByKidOrThrow(String kid) {
        Assert.hasText(kid, "kid cannot be empty");
        return authorizationRepository.findById(kid)
            .filter(OAuth2KeyEntity::isActive)
            .map(authorizationMapper::toModel)
            .orElseThrow(() -> new DataRetrievalFailureException("The OAuth2Key with kid '"
                + kid + "' not found or not active in the OAuth2KeyRepository."));
    }

    @Override
    @Transactional
    public void remove(OAuth2Key key) {
        Assert.notNull(key, "key cannot be null");
        authorizationRepository.deleteById(key.getId());
    }
}
