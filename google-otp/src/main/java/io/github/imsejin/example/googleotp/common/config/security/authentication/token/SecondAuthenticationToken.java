package io.github.imsejin.example.googleotp.common.config.security.authentication.token;

import io.github.imsejin.common.assertion.Asserts;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serial;
import java.util.Collections;

@Getter
public class SecondAuthenticationToken extends AbstractAuthenticationToken {

    @Serial
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    /**
     * Actually authenticated as a user.
     */
    public static final GrantedAuthority AUTHORITY = new SimpleGrantedAuthority("ROLE_ADMIN");

    private final Object principal;

    /**
     * Google OTP code
     */
    private String credentials;

    public SecondAuthenticationToken(Object principal, String credentials) {
        super(Collections.singletonList(AUTHORITY));
        this.principal = principal;
        this.credentials = credentials;

        Asserts.that(principal)
                .as("SecondAuthenticationToken.principal is not allowed to be null")
                .isNotNull();
        Asserts.that(credentials)
                .as("SecondAuthenticationToken.credentials must be numeric as OTP code, but it is: {0}", credentials)
                .isNotNull().isNumeric();
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }

}
