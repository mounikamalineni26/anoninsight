package com.feedback.anonymousfeedback.config;

import com.feedback.anonymousfeedback.model.User;
import com.feedback.anonymousfeedback.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner createAdmin(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder) {

        return args -> {

            if (userRepository.findByUsername("admin").isEmpty()) {

                String adminPassword = System.getenv("ADMIN_PASSWORD");

                if (adminPassword == null || adminPassword.isBlank()) {
                    throw new IllegalStateException(
                            "ADMIN_PASSWORD environment variable is not set"
                    );
                }

                User admin = new User();
                admin.setUsername("admin");
                admin.setPassword(passwordEncoder.encode(adminPassword));
                admin.setRole("ADMIN");

                userRepository.save(admin);

                System.out.println("Default admin account created.");
            }
        };
    }
}