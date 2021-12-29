package io.github.imsejin.example.googleotp.common.config.security;

import io.github.imsejin.common.assertion.Asserts;
import io.github.imsejin.example.googleotp.api.user.service.UserService;
import io.github.imsejin.example.googleotp.common.config.security.authentication.filter.DuplicatedAuthenticationProtectionFilter;
import io.github.imsejin.example.googleotp.common.config.security.authentication.filter.FirstAuthenticationFilter;
import io.github.imsejin.example.googleotp.common.config.security.authentication.filter.SecondAuthenticationFilter;
import io.github.imsejin.example.googleotp.common.config.security.authentication.handler.SecondAuthenticationSuccessHandler;
import io.github.imsejin.example.googleotp.common.config.security.authentication.provider.FirstAuthenticationProvider;
import io.github.imsejin.example.googleotp.common.config.security.authentication.provider.SecondAuthenticationProvider;
import io.github.imsejin.example.googleotp.common.config.security.authentication.token.FirstAuthenticationToken;
import io.github.imsejin.example.googleotp.common.config.security.authentication.token.SecondAuthenticationToken;
import io.github.imsejin.example.googleotp.common.config.security.tool.GoogleOtpProvider;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import javax.servlet.Filter;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter implements HttpSessionListener {

    public static final String FIRST_LOGIN_ENTRY_POINT = "/view/login/1";

    public static final String SECOND_LOGIN_ENTRY_POINT = "/view/login/2";

    public static final String FIRST_LOGIN_PATH = "/login/1";

    public static final String SECOND_LOGIN_PATH = "/login/2";

    public static final String HOME_PATH = "/view/main";

    public static final String LOGOUT_PATH = "/apis/logout";

    private static final int SESSION_TIMEOUT = (int) TimeUnit.SECONDS.convert(30, TimeUnit.MINUTES);

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(); // NoOpPasswordEncoder.getInstance()

    private final GoogleOtpProvider otpProvider = new GoogleOtpProvider();

    private final UserService service;

    private final ServerProperties props;

    @Override
    public void configure(AuthenticationManagerBuilder auth) {
        AuthenticationProvider firstProvider = new FirstAuthenticationProvider(service, passwordEncoder);
        AuthenticationProvider secondProvider = new SecondAuthenticationProvider(service, otpProvider);

        auth.authenticationProvider(firstProvider) // FirstAuthenticationFilter
                .authenticationProvider(secondProvider) // SecondAuthenticationFilter
                .eraseCredentials(true);
    }

    @Override
    public void sessionCreated(HttpSessionEvent se) {
        se.getSession().setMaxInactiveInterval(SESSION_TIMEOUT);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        authorize(http);
        login(http);
        logout(http);

        exceptionHandling(http);
        sessionManagement(http);

        http.csrf().disable().cors().disable().headers().frameOptions().disable();
    }

    private static void authorize(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // Static resources
                .antMatchers(HttpMethod.GET, staticResources()).permitAll()
                // GET /sm/023da5b10cdbae74fde6a1ba9e608edad7d2a7971debb4dd2731305a622467ae.map
                .antMatchers(HttpMethod.GET, "/favicon.ico", "/sm/*/**").permitAll()
                // Resources without authentication
                .antMatchers("/h2-console/**").permitAll()
                // 1st login resource
                .antMatchers(FIRST_LOGIN_ENTRY_POINT, FIRST_LOGIN_PATH).permitAll()
                // 2nd login resource
                .antMatchers(SECOND_LOGIN_ENTRY_POINT, SECOND_LOGIN_PATH)
                .hasAuthority(FirstAuthenticationToken.AUTHORITY.getAuthority())
                // Known resources with 2nd authentication
                .antMatchers("/view/*/**", "/apis/*/**")
                .hasAuthority(SecondAuthenticationToken.AUTHORITY.getAuthority())
                // Otherwise
                .anyRequest().denyAll();
    }

    @Override
    public void configure(WebSecurity web) {
//        web.ignoring().antMatchers(HttpMethod.GET, staticResources()).antMatchers("/favicon.ico");
    }

    private void login(HttpSecurity http) throws Exception {
        // 1st authentication
        FirstAuthenticationFilter firstFilter = new FirstAuthenticationFilter();
        AuthenticationSuccessHandler successHandler = new SimpleUrlAuthenticationSuccessHandler(SECOND_LOGIN_ENTRY_POINT);
        firstFilter.setAuthenticationManager(authenticationManager());
        firstFilter.setAuthenticationSuccessHandler(successHandler);
        firstFilter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler(FIRST_LOGIN_ENTRY_POINT + "?error"));

        // 2nd authentication
        SecondAuthenticationFilter secondFilter = new SecondAuthenticationFilter();
        secondFilter.setAuthenticationManager(authenticationManager());
        secondFilter.setAuthenticationSuccessHandler(new SecondAuthenticationSuccessHandler(HOME_PATH, service));
        secondFilter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler(SECOND_LOGIN_ENTRY_POINT + "?error"));

        // Protector for duplicated authentication.
        Filter protectionFilter = new DuplicatedAuthenticationProtectionFilter(props, FIRST_LOGIN_ENTRY_POINT,
                FIRST_LOGIN_PATH, SECOND_LOGIN_ENTRY_POINT, SECOND_LOGIN_PATH);

        http.addFilterAfter(firstFilter, LogoutFilter.class) // FirstAuthenticationFilter
                .addFilterAfter(secondFilter, FirstAuthenticationFilter.class) // SecondAuthenticationFilter
                .addFilterBefore(protectionFilter, LogoutFilter.class); // DuplicatedAuthenticationProtectionFilter
    }

    private static void logout(HttpSecurity http) throws Exception {
        http.logout().logoutUrl(LOGOUT_PATH).logoutSuccessUrl(FIRST_LOGIN_ENTRY_POINT);
    }

    private static void exceptionHandling(HttpSecurity http) throws Exception {
        http.exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(FIRST_LOGIN_ENTRY_POINT));

        // AccessDeniedException
        AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
        accessDeniedHandler.setErrorPage(FIRST_LOGIN_ENTRY_POINT);
        http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
    }

    private static void sessionManagement(HttpSecurity http) throws Exception {
        // Concurrent session management.
        http.sessionManagement()
                // If -1, allow infinite concurrent session login.
                .maximumSessions(1)
                //  If true, prevent a user from logging in and sustain the previous session.
                //  If false, allow a user to login and invalidate the previous session.
                .maxSessionsPreventsLogin(false);

        // Protection against session fixation attack.
        http.sessionManagement()
                .sessionFixation().changeSessionId();

        // Session creation policy.
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
    }

    @SneakyThrows
    private static String[] staticResources() {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        URL url = classLoader.getResource(".");

        Asserts.that(url).isNotNull().predicate(it -> url.getProtocol().equals("file"));

        Path staticResourcePath = Paths.get(url.toURI().resolve("static"));

        String[] directoryNames = Files.walk(staticResourcePath, 1)
                // Excludes base path.
                .skip(1)
                // Get directory name.
                .map(it -> it.getFileName().toString()).toArray(String[]::new);

        return Arrays.stream(directoryNames).map(it -> '/' + it + "/*/**").toArray(String[]::new);
    }

    @Bean
    @Primary
    PasswordEncoder passwordEncoder() {
        return this.passwordEncoder;
    }

}
