//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package io.github.susimsek.springssosamples.security.oauth2;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncodingException;

@FunctionalInterface
public interface TokenEncoder {
    Jwt encode(TokenEncoderParameters parameters, RSAKey rsaKey) throws JwtEncodingException;
}
