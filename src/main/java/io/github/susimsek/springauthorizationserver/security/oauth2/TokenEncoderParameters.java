//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package io.github.susimsek.springauthorizationserver.security.oauth2;

import com.nimbusds.jose.JWEHeader;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.util.Assert;

@RequiredArgsConstructor
public final class TokenEncoderParameters {
    private final JwsHeader jwsHeader;
    private final JWEHeader jweHeader;
    @Getter
    private final JwtClaimsSet claims;

    public static TokenEncoderParameters from(JwtClaimsSet claims) {
        Assert.notNull(claims, "claims cannot be null");
        return new TokenEncoderParameters(null, null, claims);
    }

    public static TokenEncoderParameters from(JwsHeader jwsHeader,
                                              JWEHeader jweHeader, JwtClaimsSet claims) {
        Assert.notNull(jwsHeader, "jwsHeader cannot be null");
        Assert.notNull(claims, "claims cannot be null");
        return new TokenEncoderParameters(jwsHeader, jweHeader, claims);
    }

    @Nullable
    public JWEHeader getJweHeader() {
        return this.jweHeader;
    }

    @Nullable
    public JwsHeader getJwsHeader() {
        return this.jwsHeader;
    }

}
