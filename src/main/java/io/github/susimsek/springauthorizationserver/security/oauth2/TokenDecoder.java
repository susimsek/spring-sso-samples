package io.github.susimsek.springauthorizationserver.security.oauth2;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.JWTProcessor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.util.Assert;
import org.springframework.core.convert.converter.Converter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.text.ParseException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

@RequiredArgsConstructor
public final class TokenDecoder implements JwtDecoder {

    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";

    private final Log logger = LogFactory.getLog(this.getClass());
    private final OAuth2KeyService oAuth2KeyService;
    private final JWTProcessor<SecurityContext> jwtProcessor;
    private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();
    private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter =
        MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());


    public void setJwtValidator(OAuth2TokenValidator<Jwt> jwtValidator) {
        Assert.notNull(jwtValidator, "jwtValidator cannot be null");
        this.jwtValidator = jwtValidator;
    }

    public void setClaimSetConverter(Converter<Map<String, Object>, Map<String, Object>> claimSetConverter) {
        Assert.notNull(claimSetConverter, "claimSetConverter cannot be null");
        this.claimSetConverter = claimSetConverter;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        JWT jwt;
        if (isJweToken(token)) {
            JWEObject jweObject = this.parseJwe(token);
            JWEHeader jweHeader = jweObject.getHeader();
            String jweKeyId = jweHeader.getKeyID();
            OAuth2Key oAuth2Key = oAuth2KeyService.findByKidOrThrow(jweKeyId);
            decrypt(jweObject, oAuth2Key.toRSAKey());
            jwt = getSignedJWT(jweObject);
        } else {
            jwt = this.parseJwt(token);
        }
        Jwt createdJwt = this.createJwt(token, jwt);
        return this.validateJwt(createdJwt);
    }

    private JWEObject parseJwe(String token) {
        try {
            return JWEObject.parse(token);
        } catch (Exception ex) {
            this.logger.trace("Failed to parse token", ex);
            if (ex instanceof ParseException) {
                throw new BadJwtException(DECODING_ERROR_MESSAGE_TEMPLATE.formatted("Malformed token"), ex);
            } else {
                throw new BadJwtException(DECODING_ERROR_MESSAGE_TEMPLATE.formatted(ex.getMessage()), ex);
            }
        }
    }

    private JWT parseJwt(String token) {
        try {
            return JWTParser.parse(token);
        } catch (Exception ex) {
            this.logger.trace("Failed to parse token", ex);
            if (ex instanceof ParseException) {
                throw new BadJwtException(DECODING_ERROR_MESSAGE_TEMPLATE.formatted("Malformed token"), ex);
            } else {
                throw new BadJwtException(DECODING_ERROR_MESSAGE_TEMPLATE.formatted(ex.getMessage()), ex);
            }
        }
    }

    private void decrypt(JWEObject jweObject, RSAKey rsaKey) {
        try {
            RSADecrypter decrypter = new RSADecrypter(rsaKey);
            jweObject.decrypt(decrypter);
        } catch (JOSEException e) {
            throw new JwtException(DECODING_ERROR_MESSAGE_TEMPLATE.formatted("Unable to decrypt token"), e);
        }
    }

    private SignedJWT getSignedJWT(JWEObject jweObject) {
        return jweObject.getPayload().toSignedJWT();
    }

    private Jwt createJwt(String token, JWT parsedJwt) {
        try {
            JWTClaimsSet jwtClaimsSet = this.jwtProcessor.process(parsedJwt, null);
            Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
            Map<String, Object> claims = this.claimSetConverter.convert(jwtClaimsSet.getClaims());
            return Jwt.withTokenValue(token)
                .headers(h -> h.putAll(headers))
                .claims(c -> c.putAll(claims))
                .build();
        } catch (RemoteKeySourceException ex) {
            this.logger.trace("Failed to retrieve JWK set", ex);
            if (ex.getCause() instanceof ParseException) {
                throw new JwtException(DECODING_ERROR_MESSAGE_TEMPLATE.formatted("Malformed Jwk set"), ex);
            } else {
                throw new JwtException(DECODING_ERROR_MESSAGE_TEMPLATE.formatted(ex.getMessage()), ex);
            }
        } catch (JOSEException ex) {
            this.logger.trace("Failed to process JWT", ex);
            throw new JwtException(DECODING_ERROR_MESSAGE_TEMPLATE.formatted(ex.getMessage()), ex);
        } catch (Exception ex) {
            this.logger.trace("Failed to process JWT", ex);
            if (ex.getCause() instanceof ParseException) {
                throw new BadJwtException(DECODING_ERROR_MESSAGE_TEMPLATE.formatted("Malformed payload"), ex);
            } else {
                throw new BadJwtException(DECODING_ERROR_MESSAGE_TEMPLATE.formatted(ex.getMessage()), ex);
            }
        }
    }

    private Jwt validateJwt(Jwt jwt) {
        OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);
        if (result.hasErrors()) {
            throw new JwtValidationException(getJwtValidationExceptionMessage(result.getErrors()), result.getErrors());
        }
        return jwt;
    }

    public boolean isJweToken(String token) {
        return token.split("\\.").length == 5;
    }

    private String getJwtValidationExceptionMessage(Iterable<OAuth2Error> errors) {
        StringBuilder message = new StringBuilder("Unable to validate Jwt: ");
        for (OAuth2Error error : errors) {
            message.append(error.getDescription()).append(" ");
        }
        return message.toString().trim();
    }
}
