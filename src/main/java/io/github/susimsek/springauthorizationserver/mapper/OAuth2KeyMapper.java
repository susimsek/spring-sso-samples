package io.github.susimsek.springauthorizationserver.mapper;

import com.nimbusds.jose.jwk.KeyUse;
import io.github.susimsek.springauthorizationserver.entity.OAuth2KeyEntity;
import io.github.susimsek.springauthorizationserver.security.EncryptionConstants;
import io.github.susimsek.springauthorizationserver.security.oauth2.OAuth2Key;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface OAuth2KeyMapper {

    default OAuth2KeyEntity toEntity(OAuth2Key model) {
        if (model == null) {
            return null;
        }

        OAuth2KeyEntity entity = new OAuth2KeyEntity();
        entity.setId(model.getId());
        entity.setType(model.getType());
        entity.setAlgorithm(model.getAlgorithm() != null ? model.getAlgorithm().getName() : null);
        entity.setPublicKey(publicKeyToString(model.getPublicKey()));
        entity.setPrivateKey(privateKeyToString(model.getPrivateKey()));
        entity.setActive(model.isActive());
        entity.setKid(model.getKid());
        entity.setUse(keyUseToString(model.getUse()));

        return entity;
    }


    default OAuth2Key toModel(OAuth2KeyEntity entity) {
        if (entity == null) {
            return null;
        }

        return OAuth2Key.builder()
            .id(entity.getId())
            .type(entity.getType())
            .algorithm(entity.getAlgorithm())
            .publicKey(entity.getPublicKey())
            .privateKey(entity.getPrivateKey())
            .active(entity.isActive())
            .kid(entity.getKid())
            .use(entity.getUse())
            .build();
    }

    List<OAuth2Key> toModelList(List<OAuth2KeyEntity> entities);

    static String publicKeyToString(PublicKey publicKey) {
        if (publicKey == null) {
            return null;
        }
        String encodedKey = new String(publicKey.getEncoded(), StandardCharsets.UTF_8);
        return encodedKey.replace(EncryptionConstants.PUBLIC_KEY_HEADER, "")
            .replace(EncryptionConstants.PUBLIC_KEY_FOOTER, "");
    }

    static String privateKeyToString(PrivateKey privateKey) {
        if (privateKey == null) {
            return null;
        }
        String encodedKey = new String(privateKey.getEncoded(), StandardCharsets.UTF_8);
        return encodedKey.replace(EncryptionConstants.PRIVATE_KEY_HEADER, "")
            .replace(EncryptionConstants.PRIVATE_KEY_FOOTER, "");
    }

    static String keyUseToString(KeyUse keyUse) {
        return keyUse == null ? null : keyUse.identifier();
    }
}
