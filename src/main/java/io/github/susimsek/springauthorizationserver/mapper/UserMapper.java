package io.github.susimsek.springauthorizationserver.mapper;

import io.github.susimsek.springauthorizationserver.entity.UserEntity;
import org.mapstruct.Mapper;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.stream.Collectors;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

@Mapper(componentModel = "spring")
public interface UserMapper {

    default UserDetails toDto(UserEntity userEntity) {
        return User.builder()
            .username(userEntity.getUsername())
            .password(userEntity.getPassword())
            .authorities(userEntity.getUserRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getRole().getName()))
                .collect(Collectors.toSet()))
            .accountExpired(false)
            .accountLocked(false)
            .credentialsExpired(false)
            .disabled(!userEntity.getEnabled())
            .build();
    }

    default OidcUserInfo toOidcUserInfo(UserEntity userEntity) {
        return OidcUserInfo.builder()
            .subject(userEntity.getUsername())
            .name(userEntity.getFirstName() + " " + userEntity.getLastName())
            .givenName(userEntity.getFirstName())
            .familyName(userEntity.getLastName())
            .nickname(userEntity.getUsername())
            .preferredUsername(userEntity.getUsername())
            .email(userEntity.getEmail())
            .emailVerified(true)
            .updatedAt(userEntity.getUpdatedAt().toString())
            .build();
    }
}
