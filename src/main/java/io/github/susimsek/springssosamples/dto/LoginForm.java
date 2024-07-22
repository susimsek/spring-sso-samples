package io.github.susimsek.springssosamples.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginForm(
    @NotBlank(message = "{validation.field.notBlank}") String username,
    @NotBlank(message = "{validation.field.notBlank}") String password
) {}
