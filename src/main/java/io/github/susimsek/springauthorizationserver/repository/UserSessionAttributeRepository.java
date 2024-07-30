package io.github.susimsek.springauthorizationserver.repository;

import io.github.susimsek.springauthorizationserver.entity.UserSessionAttributeEntity;
import io.github.susimsek.springauthorizationserver.entity.UserSessionAttributeId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserSessionAttributeRepository extends JpaRepository<UserSessionAttributeEntity, UserSessionAttributeId> {

    UserSessionAttributeEntity findBySessionIdAndAttributeName(String sessionId, String attributeName);

    void deleteBySessionIdAndAttributeName(String sessionId, String attributeName);
}
