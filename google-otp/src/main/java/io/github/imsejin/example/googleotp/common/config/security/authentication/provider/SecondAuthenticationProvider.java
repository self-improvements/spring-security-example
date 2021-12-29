package io.github.imsejin.example.googleotp.common.config.security.authentication.provider;

import io.github.imsejin.example.googleotp.api.user.model.User;
import io.github.imsejin.example.googleotp.api.user.service.UserService;
import io.github.imsejin.example.googleotp.common.config.security.authentication.token.SecondAuthenticationToken;
import io.github.imsejin.example.googleotp.common.config.security.tool.GoogleOtpProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@RequiredArgsConstructor
public class SecondAuthenticationProvider implements AuthenticationProvider {

    private final UserService service;

    private final GoogleOtpProvider otpProvider;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();

        User user = service.findUserById(username);
        if (user == null) throw new UsernameNotFoundException("Cannot find a user: " + username);

        String secretKey = user.getOtpSecretKey();
        String otpCode = authentication.getCredentials().toString();
        if (!otpProvider.validation(secretKey, otpCode)) {
            throw new BadCredentialsException("Invalid OTP for user: " + username);
        }

        Authentication token = new SecondAuthenticationToken(user, otpCode);
        token.setAuthenticated(true); // If not, FilterSecurityInterceptor will re-authenticate by delegating AuthenticationManager.

        return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SecondAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
