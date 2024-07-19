package io.github.susimsek.springssosamples.security.oauth2;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

@RequiredArgsConstructor
public class JweEncoder implements JwtEncoder {

    private static final String ENCODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to encode the Jwt: %s";
    private final KeyPair jwtKeyPair;

    @Override
    public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
        Assert.notNull(parameters, "parameters cannot be null");

        JwtClaimsSet claims = parameters.getClaims();
        JwsHeader headers = parameters.getJwsHeader();
        if (headers == null) {
            headers = JwsHeader.with(SignatureAlgorithm.RS256).build();
        }

        JWSHeader jwsHeader = convert(headers);
        JWTClaimsSet claimsSet = convert(claims);

        SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
        JWSSigner signer = createSigner(this.jwtKeyPair);

        try {
            signedJWT.sign(signer);
            JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .contentType("JWT")
                .build();
            JWEObject jweObject = new JWEObject(jweHeader,
                new Payload(signedJWT));
            RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) this.jwtKeyPair.getPublic());
            jweObject.encrypt(encrypter);
            return Jwt.withTokenValue(jweObject.serialize())
                .headers(h -> h.putAll(jweHeader.toJSONObject()))
                .claims(c -> c.putAll(claims.getClaims()))
                .build();
        } catch (JOSEException e) {
            throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Unable to encrypt JWT"), e);
        }
    }

    private static JWSHeader convert(JwsHeader headers) {
        JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.parse(headers.getAlgorithm().getName()));
        if (headers.getJwkSetUrl() != null) {
            builder.jwkURL(convertAsURI("jku", headers.getJwkSetUrl()));
        }

        Map<String, Object> jwk = headers.getJwk();
        if (!CollectionUtils.isEmpty(jwk)) {
            try {
                builder.jwk(JWK.parse(jwk));
            } catch (Exception ex) {
                throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Unable to convert 'jwk' JOSE header"), ex);
            }
        }

        String keyId = headers.getKeyId();
        if (StringUtils.hasText(keyId)) {
            builder.keyID(keyId);
        }

        if (headers.getX509Url() != null) {
            builder.x509CertURL(convertAsURI("x5u", headers.getX509Url()));
        }

        List<String> x509CertificateChain = headers.getX509CertificateChain();
        if (!CollectionUtils.isEmpty(x509CertificateChain)) {
            builder.x509CertChain(convertCertificateChain(x509CertificateChain));
        }

        String x509SHA256Thumbprint = headers.getX509SHA256Thumbprint();
        if (StringUtils.hasText(x509SHA256Thumbprint)) {
            builder.x509CertSHA256Thumbprint(new Base64URL(x509SHA256Thumbprint));
        }

        String type = headers.getType();
        if (StringUtils.hasText(type)) {
            builder.type(new JOSEObjectType(type));
        }

        String contentType = headers.getContentType();
        if (StringUtils.hasText(contentType)) {
            builder.contentType(contentType);
        }

        Set<String> critical = headers.getCritical();
        if (!CollectionUtils.isEmpty(critical)) {
            builder.criticalParams(critical);
        }

        Map<String, Object> customHeaders = new HashMap<>();
        headers.getHeaders().forEach((name, value) -> {
            if (!JWSHeader.getRegisteredParameterNames().contains(name)) {
                customHeaders.put(name, value);
            }
        });
        if (!customHeaders.isEmpty()) {
            builder.customParams(customHeaders);
        }

        return builder.build();
    }

    private static JWTClaimsSet convert(JwtClaimsSet claims) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        Object issuer = claims.getClaim("iss");
        if (issuer != null) {
            builder.issuer(issuer.toString());
        }

        String subject = claims.getSubject();
        if (StringUtils.hasText(subject)) {
            builder.subject(subject);
        }

        List<String> audience = claims.getAudience();
        if (!CollectionUtils.isEmpty(audience)) {
            builder.audience(audience);
        }

        Instant expiresAt = claims.getExpiresAt();
        if (expiresAt != null) {
            builder.expirationTime(Date.from(expiresAt));
        }

        Instant notBefore = claims.getNotBefore();
        if (notBefore != null) {
            builder.notBeforeTime(Date.from(notBefore));
        }

        Instant issuedAt = claims.getIssuedAt();
        if (issuedAt != null) {
            builder.issueTime(Date.from(issuedAt));
        }

        String jwtId = claims.getId();
        if (StringUtils.hasText(jwtId)) {
            builder.jwtID(jwtId);
        }

        Map<String, Object> customClaims = new HashMap<>();
        claims.getClaims().forEach((name, value) -> {
            if (!JWTClaimsSet.getRegisteredNames().contains(name)) {
                customClaims.put(name, value);
            }
        });
        if (!customClaims.isEmpty()) {
            Objects.requireNonNull(builder);
            customClaims.forEach(builder::claim);
        }

        return builder.build();
    }

    private static URI convertAsURI(String header, URL url) {
        try {
            return url.toURI();
        } catch (Exception ex) {
            throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Unable to convert '" + header + "' JOSE header to a URI"), ex);
        }
    }

    private static List<Base64> convertCertificateChain(List<String> x509CertificateChain) {
        List<Base64> x5cList = new ArrayList<>();
        x509CertificateChain.forEach(x5c -> x5cList.add(new Base64(x5c)));
        return x5cList;
    }

    private static JWSSigner createSigner(KeyPair jwtKeyPair) {
        return new RSASSASigner(jwtKeyPair.getPrivate());
    }
}
