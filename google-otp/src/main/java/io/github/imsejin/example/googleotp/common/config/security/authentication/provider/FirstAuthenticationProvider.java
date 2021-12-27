package io.github.imsejin.example.googleotp.common.config.security.authentication.provider;

import io.github.imsejin.example.googleotp.api.user.model.User;
import io.github.imsejin.example.googleotp.api.user.service.UserService;
import io.github.imsejin.example.googleotp.common.config.security.authentication.token.FirstAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
public class FirstAuthenticationProvider implements AuthenticationProvider {

    private final UserService service;

    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();

        User user = service.findUserById(username);
        if (user == null) throw new UsernameNotFoundException("Cannot find a user: " + username);

        String rawPassword = authentication.getCredentials().toString();
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new BadCredentialsException("Bad credentials for user: " + username);
        }

        Authentication token = new FirstAuthenticationToken(user, rawPassword);
        token.setAuthenticated(true); // If not, FilterSecurityInterceptor will re-authenticate by delegating AuthenticationManager.

        return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return FirstAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
