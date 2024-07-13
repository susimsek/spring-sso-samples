package io.github.susimsek.springssosamples.repository;


import io.github.susimsek.springssosamples.entity.OAuth2RegisteredClientEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2RegisteredClientRepository extends JpaRepository<OAuth2RegisteredClientEntity, String> {
    Optional<OAuth2RegisteredClientEntity> findByClientId(String clientId);
    Integer countByClientId(String clientId);
    Integer countByClientSecret(String clientSecret);
}