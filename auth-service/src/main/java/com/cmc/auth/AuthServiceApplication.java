package com.cmc.auth;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthServiceApplication {
    public static void main(String[] args) {
        try {
            Dotenv dotenv = Dotenv.configure().directory("./").ignoreIfMissing().load();
            dotenv.entries().forEach(e -> System.setProperty(e.getKey(), e.getValue()));
            System.out.println("✅ Config loaded form .env");
        } catch (Exception e) {
            System.err.println("⚠️ .env not found, using system env.");
        }
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}