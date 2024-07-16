package io.github.susimsek.springssosamples.repository;


import static io.github.susimsek.springssosamples.cache.CacheName.OAUTH2_CLIENT_ENTITY_BY_CLIENT_ID_CACHE;
import static io.github.susimsek.springssosamples.cache.CacheName.OAUTH2_CLIENT_ENTITY_COUNT_BY_CLIENT_ID_CACHE;
import static io.github.susimsek.springssosamples.cache.CacheName.OAUTH2_CLIENT_ENTITY_COUNT_BY_CLIENT_SECRET_CACHE;

import io.github.susimsek.springssosamples.entity.OAuth2RegisteredClientEntity;
import java.util.Optional;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2RegisteredClientRepository extends JpaRepository<OAuth2RegisteredClientEntity, String> {
    @Cacheable(cacheNames = OAUTH2_CLIENT_ENTITY_BY_CLIENT_ID_CACHE)
    Optional<OAuth2RegisteredClientEntity> findByClientId(String clientId);

    @Cacheable(cacheNames = OAUTH2_CLIENT_ENTITY_COUNT_BY_CLIENT_ID_CACHE)
    Integer countByClientId(String clientId);

    @Cacheable(cacheNames = OAUTH2_CLIENT_ENTITY_COUNT_BY_CLIENT_SECRET_CACHE)
    Integer countByClientSecret(String clientSecret);
}
