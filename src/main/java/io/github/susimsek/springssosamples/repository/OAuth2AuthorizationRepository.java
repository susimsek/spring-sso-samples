package io.github.susimsek.springssosamples.repository;


import io.github.susimsek.springssosamples.entity.OAuth2AuthorizationEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface OAuth2AuthorizationRepository
    extends JpaRepository<OAuth2AuthorizationEntity, String>,
    JpaSpecificationExecutor<OAuth2AuthorizationEntity> {
}