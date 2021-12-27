package io.github.imsejin.example.googleotp.common.config.security.tool;

import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class GoogleOtpProvider {

    private static final String GOOGLE_URL = "https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=";

    public String provide(String username) {
        String secretKey = generateSecretKey();
        return getGoogleAuthenticatorBarcode(secretKey, username);
    }

    public boolean validation(String secretKey, String code) {
        return getTOTPCode(secretKey).equals(code);
    }

    private static String generateSecretKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        return new Base32().encodeToString(bytes);
    }

    @SneakyThrows
    private static String getGoogleAuthenticatorBarcode(String secretKey, String account) {
        return GOOGLE_URL + "otpauth://totp/"
                + URLEncoder.encode(account, StandardCharsets.UTF_8.name()).replace("+", "%20") + "?secret="
                + URLEncoder.encode(secretKey, StandardCharsets.UTF_8.name()).replace("+", "%20");
    }

    private static String getTOTPCode(String secretKey) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey);
        String hexKey = Hex.encodeHexString(bytes);

        return TOTP.getOTP(hexKey);
    }

}
