package io.github.susimsek.springauthorizationserver.repository;

import io.github.susimsek.springauthorizationserver.entity.UserSessionEntity;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSessionEntity, String> {

    @Query("SELECT s FROM UserSessionEntity s LEFT JOIN FETCH s.attributes WHERE s.sessionId = :sessionId")
    Optional<UserSessionEntity> findBySessionId(@Param("sessionId") String sessionId);

    @Query("SELECT s FROM UserSessionEntity s LEFT JOIN FETCH s.attributes WHERE s.principalName = :principalName")
    List<UserSessionEntity> findByPrincipalName(@Param("principalName") String principalName);

    void deleteBySessionId(String sessionId);

    void deleteByExpiryTimeBefore(Instant now);
}
