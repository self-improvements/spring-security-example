package io.github.imsejin.example.googleotp.common.config.security.authentication.filter;

import io.github.imsejin.common.util.StringUtils;
import io.github.imsejin.example.googleotp.api.user.model.User;
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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SecondAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public static final String DEFAULT_FORM_SECRET_KEY = "otp-code";

    private static final RequestMatcher DEFAULT_REQUEST_MATCHER = new AntPathRequestMatcher(
            WebSecurityConfig.SECOND_LOGIN_PATH, HttpMethod.POST.name());

    public SecondAuthenticationFilter() {
        super(DEFAULT_REQUEST_MATCHER);
    }

    public SecondAuthenticationFilter(String requestPattern) {
        super(new AntPathRequestMatcher(requestPattern, HttpMethod.POST.name()));
    }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        boolean required = super.requiresAuthentication(request, response);

        Authentication token = SecurityContextHolder.getContext().getAuthentication();
        if (token == null) return false; // Authentication must be in SecurityContext when 1st login.

        // When fully authenticated.
        for (GrantedAuthority auth : token.getAuthorities()) {
            if (auth.getAuthority().equals(SecondAuthenticationToken.AUTHORITY.getAuthority())) return false;
        }

        required &= (token instanceof FirstAuthenticationToken);
        required &= (token.getPrincipal() instanceof User);

        return required;
    }

    @Override
    public final Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        String username = user.getId(); // getParamFromRequest(request, DEFAULT_FORM_USERNAME_KEY);
        String secretKey = getParamFromRequest(request, DEFAULT_FORM_SECRET_KEY);

        Authentication token = new SecondAuthenticationToken(username, secretKey);

        return super.getAuthenticationManager().authenticate(token);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
            throws IOException, ServletException {
        // DO NOT CLEAR SECURITY CONTEXT; sustain FirstAuthenticationToken in SecurityContext.
        super.getFailureHandler().onAuthenticationFailure(request, response, failed);
    }

    @NonNull
    private static String getParamFromRequest(HttpServletRequest request, String name) {
        return StringUtils.ifNullOrEmpty(request.getParameter(name), "").trim();
    }

}
