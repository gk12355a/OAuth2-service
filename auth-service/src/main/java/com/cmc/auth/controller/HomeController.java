package com.cmc.auth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/")
    public String home(Authentication authentication) {
        if (authentication != null) {
            return "<h1>Xin chào " + authentication.getName() + "!</h1>" +
                   "<p>Bạn đang ở Auth Service (Port 9000).</p>" +
                   "<p>Bạn đã đăng nhập thành công. Hãy dùng link OAuth2 để kết nối ứng dụng.</p>";
        }
        return "<h1>Auth Service</h1><p>Vui lòng đăng nhập.</p>";
    }
}