package io.github.susimsek.springssosamples.repository;


import static io.github.susimsek.springssosamples.cache.CacheName.ROLE_ENTITY_BY_NAME_CACHE;
import static io.github.susimsek.springssosamples.cache.CacheName.USER_ENTITY_BY_EMAIL_CACHE;
import static io.github.susimsek.springssosamples.cache.CacheName.USER_ENTITY_BY_USERNAME_CACHE;

import io.github.susimsek.springssosamples.entity.UserEntity;
import java.util.Optional;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, String> {
    @Cacheable(cacheNames = USER_ENTITY_BY_USERNAME_CACHE)
    Optional<UserEntity> findByUsername(String username);

    @Cacheable(cacheNames = USER_ENTITY_BY_EMAIL_CACHE)
    Optional<UserEntity> findByEmail(String email);
}
