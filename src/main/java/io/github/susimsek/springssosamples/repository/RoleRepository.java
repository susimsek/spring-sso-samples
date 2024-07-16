package io.github.susimsek.springssosamples.repository;

import static io.github.susimsek.springssosamples.cache.CacheName.ROLE_ENTITY_BY_NAME_CACHE;

import io.github.susimsek.springssosamples.entity.RoleEntity;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<RoleEntity, String> {

    @Cacheable(cacheNames = ROLE_ENTITY_BY_NAME_CACHE)
    Optional<RoleEntity> findByName(String name);
}
