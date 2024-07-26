package io.github.susimsek.springauthorizationserver.repository;

import io.github.susimsek.springauthorizationserver.entity.OAuth2AuthorizationConsentEntity;
import io.github.susimsek.springauthorizationserver.entity.OAuth2AuthorizationConsentId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OAuth2AuthorizationConsentRepository
    extends JpaRepository<OAuth2AuthorizationConsentEntity, OAuth2AuthorizationConsentId> {
}
