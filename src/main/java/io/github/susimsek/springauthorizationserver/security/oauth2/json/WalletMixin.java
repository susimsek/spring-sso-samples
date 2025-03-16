package io.github.susimsek.springauthorizationserver.security.oauth2.json;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeName;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
@JsonTypeName("io.github.susimsek.springauthorizationserver.security.oauth2.wallet.Wallet")
public abstract class WalletMixin {
}
