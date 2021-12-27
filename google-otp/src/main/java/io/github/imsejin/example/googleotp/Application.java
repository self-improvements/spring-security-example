package io.github.imsejin.example.googleotp;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.stereotype.Component;

@EnableAsync
@EnableScheduling
@SpringBootApplication
@ConfigurationPropertiesScan
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Component
    @RequiredArgsConstructor
    private static class AppRunner implements ApplicationRunner {
        @Override
        public void run(ApplicationArguments args) throws Exception {

        }
    }

}
