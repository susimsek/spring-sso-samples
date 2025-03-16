package io.github.susimsek.springauthorizationserver.security.oauth2.wallet;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Wallet {
    private String walletAddress;
    private String walletSignature;
    private String walletMessage;
}
