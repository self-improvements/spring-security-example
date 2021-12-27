package io.github.imsejin.example.googleotp.common.config.security.authentication.filter;

import io.github.imsejin.common.util.StringUtils;
import io.github.imsejin.example.googleotp.common.config.security.WebSecurityConfig;
import io.github.imsejin.example.googleotp.common.config.security.authentication.token.FirstAuthenticationToken;
import io.github.imsejin.example.googleotp.common.config.security.authentication.token.SecondAuthenticationToken;
import org.springframework.http.HttpMethod;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FirstAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public static final String DEFAULT_FORM_USERNAME_KEY = "username";

    public static final String DEFAULT_FORM_PASSWORD_KEY = "password";

    private static final RequestMatcher DEFAULT_REQUEST_MATCHER = new AntPathRequestMatcher(
            WebSecurityConfig.FIRST_LOGIN_PATH, HttpMethod.POST.name());

    public FirstAuthenticationFilter() {
        super(DEFAULT_REQUEST_MATCHER);
    }

    public FirstAuthenticationFilter(String requestPattern) {
        super(new AntPathRequestMatcher(requestPattern, HttpMethod.POST.name()));
    }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        boolean required = super.requiresAuthentication(request, response);

        Authentication token = SecurityContextHolder.getContext().getAuthentication();
        if (token == null) return required;

        // When fully authenticated.
        for (GrantedAuthority auth : token.getAuthorities()) {
            if (auth.getAuthority().equals(SecondAuthenticationToken.AUTHORITY.getAuthority())) return false;
        }

        return required;
    }

    @Override
    public final Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        String username = getParamFromRequest(request, DEFAULT_FORM_USERNAME_KEY);
        String rawPassword = getParamFromRequest(request, DEFAULT_FORM_PASSWORD_KEY);

        Authentication token = new FirstAuthenticationToken(username, rawPassword);

        return super.getAuthenticationManager().authenticate(token);
    }

    @NonNull
    private static String getParamFromRequest(HttpServletRequest request, String name) {
        return StringUtils.ifNullOrEmpty(request.getParameter(name), "").trim();
    }

}
