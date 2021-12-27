package io.github.imsejin.example.googleotp.common.config.security.authentication.token;

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
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }

}
