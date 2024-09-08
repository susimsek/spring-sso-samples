package io.github.susimsek.springauthorizationserver.repository;

import static io.github.susimsek.springauthorizationserver.cache.CacheName.OAUTH2_AUTHORIZATION_ENTITY_BY_SPECIFICATION_CACHE;

import io.github.susimsek.springauthorizationserver.entity.OAuth2AuthorizationEntity;
import java.util.Optional;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.lang.NonNull;


public interface OAuth2AuthorizationRepository
    extends JpaRepository<OAuth2AuthorizationEntity, String>,
    JpaSpecificationExecutor<OAuth2AuthorizationEntity> {

    @Override
    @NonNull
    @Cacheable(cacheNames = OAUTH2_AUTHORIZATION_ENTITY_BY_SPECIFICATION_CACHE,
        keyGenerator = "specificationKeyGenerator")
    Optional<OAuth2AuthorizationEntity> findOne(@NonNull Specification<OAuth2AuthorizationEntity> spec);
}
