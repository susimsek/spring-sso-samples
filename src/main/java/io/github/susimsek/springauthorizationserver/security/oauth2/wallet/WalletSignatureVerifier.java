package io.github.susimsek.springauthorizationserver.security.oauth2.wallet;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;
import java.util.Arrays;
import java.math.BigInteger;

@Component
@Slf4j
public class WalletSignatureVerifier {

    public boolean verify(String msg, String sig, String walletAddress) {
        String recovered = ecRecover(msg, sig);
        return recovered != null && recovered.equalsIgnoreCase(walletAddress);
    }

    public static String ecRecover(String msg, String sig) {
        byte[] sigBytes = Numeric.hexStringToByteArray(sig);
        Sign.SignatureData sigData = sigFromByteArray(sigBytes);
        if (sigData == null) {
            log.error("Invalid signature format for sig: {}", sig);
            return null;
        }
        try {
            BigInteger key = Sign.signedPrefixedMessageToKey(msg.getBytes(), sigData);
            return ("0x" + Keys.getAddress(key)).toLowerCase();
        } catch (Exception e) {
            log.error("SignatureException, msg:{}, sig:{}: {}", msg, sig, e.getMessage());
            return null;
        }
    }

    public static Sign.SignatureData sigFromByteArray(byte[] sig) {
        if (sig.length < 64 || sig.length > 65) {
            return null;
        }
        byte v = sig[64];
        if (v < 27) {
            v += 27;
        }
        byte[] r = Arrays.copyOfRange(sig, 0, 32);
        byte[] s = Arrays.copyOfRange(sig, 32, 64);
        return new Sign.SignatureData(v, r, s);
    }
}
