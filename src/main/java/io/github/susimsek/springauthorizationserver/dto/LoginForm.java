package io.github.susimsek.springauthorizationserver.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginForm {

    @NotBlank(message = "{validation.field.notBlank}")
    private String username;

    @NotBlank(message = "{validation.field.notBlank}")
    private String password;
}
