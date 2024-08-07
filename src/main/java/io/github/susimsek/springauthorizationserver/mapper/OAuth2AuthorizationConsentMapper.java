package io.github.susimsek.springauthorizationserver.mapper;

import io.github.susimsek.springauthorizationserver.entity.OAuth2AuthorizationConsentEntity;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.mapstruct.Mapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.util.StringUtils;

@Mapper(componentModel = "spring")
public interface OAuth2AuthorizationConsentMapper {

    default OAuth2AuthorizationConsentEntity toEntity(OAuth2AuthorizationConsent model) {
        if (model == null) {
            return null;
        }

        OAuth2AuthorizationConsentEntity entity = new OAuth2AuthorizationConsentEntity();
        entity.setRegisteredClientId(model.getRegisteredClientId());
        entity.setPrincipalName(model.getPrincipalName());
        entity.setAuthorities(model.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(",")));

        return entity;
    }

    default OAuth2AuthorizationConsent toModel(OAuth2AuthorizationConsentEntity entity) {
        if (entity == null) {
            return null;
        }

        Set<GrantedAuthority> authorities = new HashSet<>();
        if (StringUtils.hasText(entity.getAuthorities())) {
            for (String authority : entity.getAuthorities().split(",")) {
                authorities.add(new SimpleGrantedAuthority(authority));
            }
        }

        return OAuth2AuthorizationConsent.withId(entity.getRegisteredClientId(), entity.getPrincipalName())
            .authorities(grantedAuthorities -> grantedAuthorities.addAll(authorities))
            .build();
    }
}
