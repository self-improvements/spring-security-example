package io.github.imsejin.example.googleotp.common.config.security.authentication.filter;

import io.github.imsejin.common.util.StringUtils;
import io.github.imsejin.example.googleotp.common.config.security.WebSecurityConfig;
import io.github.imsejin.example.googleotp.common.config.security.authentication.token.SecondAuthenticationToken;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

public class DuplicatedAuthenticationProtectionFilter implements Filter {

    private final String contextPath;

    private final List<String> targetUrls;

    public DuplicatedAuthenticationProtectionFilter(String... targetUrls) {
        this.contextPath = "";
        this.targetUrls = List.of(targetUrls);
    }

    public DuplicatedAuthenticationProtectionFilter(ServerProperties props, String... targetUrls) {
        this.contextPath = props.getServlet().getContextPath();
        this.targetUrls = List.of(targetUrls);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!isRequired(request)) {
            chain.doFilter(request, response);
            return;
        }

        // DO NOT INVOKE 'FilterChain.doFilter(request, response)';
        // because prevent exception from occurring.
        response.sendRedirect(WebSecurityConfig.HOME_PATH);
    }

    private boolean isRequired(HttpServletRequest request) {
        Authentication token = SecurityContextHolder.getContext().getAuthentication();
        String requestPath = request.getRequestURI();
        if (!StringUtils.isNullOrBlank(this.contextPath)) requestPath = requestPath.replaceFirst(this.contextPath, "");

        return token != null && token.isAuthenticated()
                && token instanceof SecondAuthenticationToken && this.targetUrls.contains(requestPath);
    }


}
