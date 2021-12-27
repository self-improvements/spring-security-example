package io.github.imsejin.example.googleotp.common.config.security.tool;

import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class TOTP {

    public static String getOTP(String key) {
        return getOTP(getStep(), key);
    }

    private static long getStep() {
        // 30 seconds StepSize (ID TOTP)
        return System.currentTimeMillis() / 30000;
    }

    private static String getOTP(final long step, final String key) {
        String steps = Long.toHexString(step).toUpperCase();
        while (steps.length() < 16) {
            steps = "0" + steps;
        }

        // Get the HEX in a Byte[]
        final byte[] msg = hexStr2Bytes(steps);
        final byte[] k = hexStr2Bytes(key);

        final byte[] hash = hmac_sha1(k, msg);

        // put selected bytes into result int
        final int offset = hash[hash.length - 1] & 0xf;
        final int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
        final int otp = binary % 1000000;

        String result = Integer.toString(otp);
        while (result.length() < 6) {
            result = "0" + result;
        }
        return result;
    }

    private static byte[] hexStr2Bytes(final String hex) {
        // Adding one byte to get the right conversion
        // values starting with "0" can be converted
        final byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();
        final byte[] ret = new byte[bArray.length - 1];

        // Copy all the REAL bytes, not the "first"
        System.arraycopy(bArray, 1, ret, 0, ret.length);
        return ret;
    }

    private static byte[] hmac_sha1(final byte[] keyBytes, final byte[] text) {
        try {
            final Mac hmac = Mac.getInstance("HmacSHA1");
            final SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (final GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }
}
