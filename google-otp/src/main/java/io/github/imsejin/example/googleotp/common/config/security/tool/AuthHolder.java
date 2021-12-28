package io.github.imsejin.example.googleotp.common.config.security.tool;

import io.github.imsejin.common.annotation.ExcludeFromGeneratedJacocoReport;
import io.github.imsejin.common.assertion.Asserts;
import io.github.imsejin.example.googleotp.api.user.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public final class AuthHolder {

    @ExcludeFromGeneratedJacocoReport
    private AuthHolder() {
        throw new UnsupportedOperationException(getClass().getName() + " is not allowed to instantiate");
    }

    public static User getCurrentUser() {
        Authentication token = SecurityContextHolder.getContext().getAuthentication();
        Asserts.that(token).isNotNull();

        Object user = token.getPrincipal();
        Asserts.that(user).isNotNull().isInstanceOf(User.class);

        return (User) user;
    }

}
