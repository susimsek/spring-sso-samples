package io.github.susimsek.springssosamples.repository;


import static io.github.susimsek.springssosamples.cache.CacheName.OAUTH2_CLIENT_ENTITY_BY_CLIENT_ID_CACHE;
import static io.github.susimsek.springssosamples.cache.CacheName.OAUTH2_KEY_ENTITY_BY_KID_CACHE;

import io.github.susimsek.springssosamples.entity.OAuth2KeyEntity;
import java.util.Optional;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2KeyRepository extends JpaRepository<OAuth2KeyEntity, String> {
    @Cacheable(cacheNames = OAUTH2_KEY_ENTITY_BY_KID_CACHE)
    Optional<OAuth2KeyEntity> findByKid(String kid);
}
