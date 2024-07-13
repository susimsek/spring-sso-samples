package io.github.susimsek.springssosamples.mapper;

import io.github.susimsek.springssosamples.entity.UserEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {

    public UserDetails toDto(UserEntity userEntity) {
        return User.builder()
            .username(userEntity.getUsername())
            .password(userEntity.getPassword())
            .roles("USER")
            .accountExpired(false)
            .accountLocked(false)
            .credentialsExpired(false)
            .disabled(!userEntity.getEnabled())
            .build();
    }
}