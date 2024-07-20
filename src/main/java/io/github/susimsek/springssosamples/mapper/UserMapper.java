package io.github.susimsek.springssosamples.mapper;

import io.github.susimsek.springssosamples.entity.UserEntity;
import org.mapstruct.Mapper;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.stream.Collectors;

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
}
