package io.github.susimsek.springauthorizationserver.security;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    @NotBlank(message = "{validation.field.notBlank}")
    private String contentSecurityPolicy;
}
