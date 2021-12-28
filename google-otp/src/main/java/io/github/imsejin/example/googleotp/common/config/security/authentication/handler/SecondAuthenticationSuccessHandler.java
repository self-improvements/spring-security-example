package io.github.imsejin.example.googleotp.common.config.security.authentication.handler;

import io.github.imsejin.common.assertion.Asserts;
import io.github.imsejin.example.googleotp.api.user.model.User;
import io.github.imsejin.example.googleotp.api.user.service.UserService;
import io.github.imsejin.example.googleotp.common.config.security.tool.AuthHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SecondAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserService service;

    public SecondAuthenticationSuccessHandler(String defaultTargetUrl, UserService service) {
        super(defaultTargetUrl);
        this.service = service;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        super.onAuthenticationSuccess(request, response, authentication);

        User user = AuthHolder.getCurrentUser();
        Asserts.that(user).isSameAs(authentication.getPrincipal());

        // Save login history.
        service.createLoginHistory();
    }

}
