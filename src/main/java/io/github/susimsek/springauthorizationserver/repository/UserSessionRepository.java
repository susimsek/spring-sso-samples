package io.github.susimsek.springauthorizationserver.repository;

import static io.github.susimsek.springauthorizationserver.cache.CacheName.USER_SESSION_ENTITY_BY_PRINCIPAL_NAME_CACHE;
import static io.github.susimsek.springauthorizationserver.cache.CacheName.USER_SESSION_ENTITY_BY_SESSION_ID_CACHE;

import io.github.susimsek.springauthorizationserver.entity.UserSessionEntity;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSessionEntity, String> {

    @Cacheable(cacheNames = USER_SESSION_ENTITY_BY_SESSION_ID_CACHE)
    @Query("SELECT s FROM UserSessionEntity s LEFT JOIN FETCH s.attributes WHERE s.sessionId = :sessionId")
    Optional<UserSessionEntity> findBySessionId(@Param("sessionId") String sessionId);

    @Cacheable(cacheNames = USER_SESSION_ENTITY_BY_PRINCIPAL_NAME_CACHE)
    @Query("SELECT s FROM UserSessionEntity s LEFT JOIN FETCH s.attributes WHERE s.principalName = :principalName")
    List<UserSessionEntity> findByPrincipalName(@Param("principalName") String principalName);

    void deleteBySessionId(String sessionId);

    void deleteByExpiryTimeBefore(Instant now);
}
