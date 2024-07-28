package io.github.susimsek.springauthorizationserver.security.oauth2;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.List;
import lombok.RequiredArgsConstructor;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class OAuth2KeyJWKSource implements JWKSource<SecurityContext> {

    private final OAuth2KeyService oAuth2KeyService;

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
        return this.oAuth2KeyService.findAll().stream()
            .map(OAuth2Key::toRSAKey)
            .filter(rsaKey -> jwkSelector.getMatcher().matches(rsaKey))
            .collect(Collectors.toList());
    }
}
