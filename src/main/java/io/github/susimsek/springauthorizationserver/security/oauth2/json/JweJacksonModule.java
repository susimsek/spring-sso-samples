package io.github.susimsek.springauthorizationserver.security.oauth2.json;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;

public class JweJacksonModule extends SimpleModule {
    public JweJacksonModule() {
        super(JweJacksonModule.class.getName(), new Version(1, 0,
            0, null, null, null));
    }

    @Override
    public void setupModule(Module.SetupContext context) {
        context.setMixInAnnotations(JWEAlgorithm.class, JWEAlgorithmMixin.class);
        context.setMixInAnnotations(EncryptionMethod.class, EncryptionMethodMixin.class);
    }
}
