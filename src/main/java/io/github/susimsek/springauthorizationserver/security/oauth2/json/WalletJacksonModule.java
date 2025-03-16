package io.github.susimsek.springauthorizationserver.security.oauth2.json;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.github.susimsek.springauthorizationserver.security.oauth2.wallet.Wallet;

public class WalletJacksonModule extends SimpleModule {
    public WalletJacksonModule() {
        super(WalletJacksonModule.class.getName(), new Version(
            1, 0, 0, null, null, null));
    }

    @Override
    public void setupModule(SetupContext context) {
        context.setMixInAnnotations(Wallet.class, WalletMixin.class);
    }
}
