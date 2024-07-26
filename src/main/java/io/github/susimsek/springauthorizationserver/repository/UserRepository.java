package io.github.susimsek.springauthorizationserver.repository;

import static io.github.susimsek.springauthorizationserver.cache.CacheName.USER_ENTITY_BY_EMAIL_CACHE;
import static io.github.susimsek.springauthorizationserver.cache.CacheName.USER_ENTITY_BY_USERNAME_CACHE;

import io.github.susimsek.springauthorizationserver.entity.UserEntity;
import java.util.Optional;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, String> {
    @Cacheable(cacheNames = USER_ENTITY_BY_USERNAME_CACHE)
    Optional<UserEntity> findByUsername(String username);

    @Cacheable(cacheNames = USER_ENTITY_BY_EMAIL_CACHE)
    Optional<UserEntity> findByEmail(String email);
}
