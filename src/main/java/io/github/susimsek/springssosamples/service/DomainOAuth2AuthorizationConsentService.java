package io.github.susimsek.springssosamples.service;

import io.github.susimsek.springssosamples.entity.OAuth2AuthorizationConsentEntity;
import io.github.susimsek.springssosamples.entity.OAuth2AuthorizationConsentId;
import io.github.susimsek.springssosamples.mapper.OAuth2AuthorizationConsentMapper;
import io.github.susimsek.springssosamples.repository.OAuth2AuthorizationConsentRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

@RequiredArgsConstructor
public class DomainOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private final OAuth2AuthorizationConsentRepository repository;
    private final OAuth2AuthorizationConsentMapper mapper;

    @Override
    @Transactional
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        Optional<OAuth2AuthorizationConsentEntity> existingAuthorizationConsent =
            repository.findById(new OAuth2AuthorizationConsentId(
                authorizationConsent.getRegisteredClientId(),
                authorizationConsent.getPrincipalName()));
        if (existingAuthorizationConsent.isPresent()) {
            updateAuthorizationConsent(authorizationConsent, existingAuthorizationConsent.get());
        } else {
            insertAuthorizationConsent(authorizationConsent);
        }
    }

    private void updateAuthorizationConsent(OAuth2AuthorizationConsent authorizationConsent,
                                            OAuth2AuthorizationConsentEntity existingAuthorizationConsent) {
        OAuth2AuthorizationConsentEntity entity = mapper.toEntity(authorizationConsent);
        entity.setRegisteredClientId(existingAuthorizationConsent.getRegisteredClientId());
        entity.setPrincipalName(existingAuthorizationConsent.getPrincipalName());
        repository.save(entity);
    }

    private void insertAuthorizationConsent(OAuth2AuthorizationConsent authorizationConsent) {
        OAuth2AuthorizationConsentEntity entity = mapper.toEntity(authorizationConsent);
        repository.save(entity);
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        return repository.findById(new OAuth2AuthorizationConsentId(registeredClientId, principalName))
            .map(mapper::toModel)
            .orElse(null);
    }

    @Override
    @Transactional
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        OAuth2AuthorizationConsentId id = new OAuth2AuthorizationConsentId(
            authorizationConsent.getRegisteredClientId(),
            authorizationConsent.getPrincipalName()
        );
        repository.deleteById(id);
    }
}