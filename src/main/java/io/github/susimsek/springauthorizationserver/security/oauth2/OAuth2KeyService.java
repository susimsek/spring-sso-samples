//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package io.github.susimsek.springauthorizationserver.security.oauth2;

import java.util.List;
import org.springframework.lang.Nullable;

public interface OAuth2KeyService {

    List<OAuth2Key> findAll();

    void save(OAuth2Key key);

    void remove(OAuth2Key key);

    @Nullable
    OAuth2Key findById(String id);

    @Nullable
    OAuth2Key findByKid(String kid);

    OAuth2Key findByKidOrThrow(String kid);
}
