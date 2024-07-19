package io.github.susimsek.springssosamples.security.oauth2;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.util.Assert;
import org.springframework.core.convert.converter.Converter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.KeyPair;
import java.text.ParseException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class JweDecoder implements JwtDecoder {

    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";

    private final Log logger = LogFactory.getLog(this.getClass());
    private final KeyPair jwtKeyPair;
    private final JWTProcessor<SecurityContext> jwtProcessor;
    private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();
    private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

    public JweDecoder(KeyPair jwtKeyPair, JWTProcessor<SecurityContext> jwtProcessor) {
        Assert.notNull(jwtKeyPair, "jwtKeyPair cannot be null");
        Assert.notNull(jwtProcessor, "jwtProcessor cannot be null");
        this.jwtKeyPair = jwtKeyPair;
        this.jwtProcessor = jwtProcessor;
    }

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
        JWEObject jweObject = this.parse(token);
        decrypt(jweObject);
        SignedJWT signedJWT = getSignedJWT(jweObject);
        Jwt createdJwt = createJwt(token, signedJWT);
        return this.validateJwt(createdJwt);
    }

    private JWEObject parse(String token) {
        try {
            return JWEObject.parse(token);
        } catch (Exception ex) {
            this.logger.trace("Failed to parse token", ex);
            if (ex instanceof ParseException) {
                throw new BadJwtException(String.format("An error occurred while attempting to decode the Jwt: %s", "Malformed token"), ex);
            } else {
                throw new BadJwtException(String.format("An error occurred while attempting to decode the Jwt: %s", ex.getMessage()), ex);
            }
        }
    }

    private void decrypt(JWEObject jweObject) {
        try {
            RSADecrypter decrypter = new RSADecrypter(this.jwtKeyPair.getPrivate());
            jweObject.decrypt(decrypter);
        } catch (JOSEException e) {
            throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Unable to decrypt token"), e);
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
                throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed Jwk set"), ex);
            } else {
                throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
            }
        } catch (JOSEException ex) {
            this.logger.trace("Failed to process JWT", ex);
            throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
        } catch (Exception ex) {
            this.logger.trace("Failed to process JWT", ex);
            if (ex.getCause() instanceof ParseException) {
                throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed payload"), ex);
            } else {
                throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
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

    private String getJwtValidationExceptionMessage(Iterable<OAuth2Error> errors) {
        StringBuilder message = new StringBuilder("Unable to validate Jwt: ");
        for (OAuth2Error error : errors) {
            message.append(error.getDescription()).append(" ");
        }
        return message.toString().trim();
    }
}
