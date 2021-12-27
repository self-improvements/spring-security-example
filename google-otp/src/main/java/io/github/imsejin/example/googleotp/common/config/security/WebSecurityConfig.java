package io.github.imsejin.example.googleotp.common.config.security;

import io.github.imsejin.common.assertion.Asserts;
import io.github.imsejin.example.googleotp.api.user.service.UserService;
import io.github.imsejin.example.googleotp.common.config.security.authentication.filter.FirstAuthenticationFilter;
import io.github.imsejin.example.googleotp.common.config.security.authentication.filter.SecondAuthenticationFilter;
import io.github.imsejin.example.googleotp.common.config.security.authentication.provider.FirstAuthenticationProvider;
import io.github.imsejin.example.googleotp.common.config.security.authentication.provider.SecondAuthenticationProvider;
import io.github.imsejin.example.googleotp.common.config.security.authentication.token.FirstAuthenticationToken;
import io.github.imsejin.example.googleotp.common.config.security.authentication.token.SecondAuthenticationToken;
import io.github.imsejin.example.googleotp.common.config.security.tool.GoogleOtpProvider;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    public static final String FIRST_LOGIN_ENTRY_POINT = "/view/login/1";

    public static final String SECOND_LOGIN_ENTRY_POINT = "/view/login/2";

    public static final String FIRST_LOGIN_PATH = "/login/1";

    public static final String SECOND_LOGIN_PATH = "/login/2";

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(); // NoOpPasswordEncoder.getInstance()

    private final GoogleOtpProvider otpProvider = new GoogleOtpProvider();

    private final UserService service;

    // UsernamePasswordAuthenticationFilter
    private static void authorize(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // Static resources
                .antMatchers(HttpMethod.GET, staticResources()).permitAll()
                // GET /sm/023da5b10cdbae74fde6a1ba9e608edad7d2a7971debb4dd2731305a622467ae.map
                .antMatchers(HttpMethod.GET, "/favicon.ico", "/sm/*/**").permitAll()
                // Resources without authentication
                .antMatchers("/apis/test").permitAll()
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
    protected void configure(HttpSecurity http) throws Exception {
        authorize(http);
        login(http);
        http.exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(FIRST_LOGIN_ENTRY_POINT));

        // AccessDeniedException
        AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
        accessDeniedHandler.setErrorPage(FIRST_LOGIN_ENTRY_POINT);
        http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);

        http.csrf().disable().cors().disable().headers().frameOptions().disable();
    }

    @Override
    public void configure(WebSecurity web) {
//        web.ignoring().antMatchers(HttpMethod.GET, staticResources()).antMatchers("/favicon.ico");
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) {
        AuthenticationProvider firstProvider = new FirstAuthenticationProvider(service, passwordEncoder);
        AuthenticationProvider secondProvider = new SecondAuthenticationProvider(service, otpProvider);

//        auth.parentAuthenticationManager(null);
        auth.authenticationProvider(firstProvider) // FirstAuthenticationFilter
                .authenticationProvider(secondProvider) // SecondAuthenticationFilter
                .eraseCredentials(true);
    }

    private void login(HttpSecurity http) throws Exception {
        FirstAuthenticationFilter firstFilter = new FirstAuthenticationFilter();
        firstFilter.setAuthenticationManager(authenticationManager());
        AuthenticationSuccessHandler successHandler = new SimpleUrlAuthenticationSuccessHandler(SECOND_LOGIN_ENTRY_POINT);
        firstFilter.setAuthenticationSuccessHandler(successHandler);

        SecondAuthenticationFilter secondFilter = new SecondAuthenticationFilter();
        secondFilter.setAuthenticationManager(authenticationManager());
        secondFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            response.sendRedirect("/view/transaction/history/bsp");
            System.out.println("2nd login success: " + SecurityContextHolder.getContext().getAuthentication());
        });

        http.addFilterAfter(firstFilter, LogoutFilter.class) // FirstAuthenticationFilter
                .addFilterAfter(secondFilter, FirstAuthenticationFilter.class); // SecondAuthenticationFilter
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
