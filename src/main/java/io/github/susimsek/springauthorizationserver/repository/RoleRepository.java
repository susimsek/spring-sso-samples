package io.github.susimsek.springauthorizationserver.repository;

import static io.github.susimsek.springauthorizationserver.cache.CacheName.ROLE_ENTITY_BY_NAME_CACHE;

import io.github.susimsek.springauthorizationserver.entity.RoleEntity;
import java.util.Optional;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<RoleEntity, String> {

    @Cacheable(cacheNames = ROLE_ENTITY_BY_NAME_CACHE)
    Optional<RoleEntity> findByName(String name);
}
