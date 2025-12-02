package com.cmc.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod; // Import mới
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // [QUAN TRỌNG] Cho phép OPTIONS requests đi qua
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // Thêm dòng này
                        .requestMatchers("/auth/**", "/login", "/error", "/.well-known/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login") // URL của trang login tùy chỉnh
                        .loginProcessingUrl("/login") // URL để submit form (POST)
                        .permitAll())
                .csrf(csrf -> csrf.disable());
        // .csrf(csrf -> csrf.disable())
        // .formLogin(Customizer.withDefaults());

        return http.build();
    }
}