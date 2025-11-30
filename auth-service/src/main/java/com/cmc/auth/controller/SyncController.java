package com.cmc.auth.controller;

import com.cmc.auth.config.RabbitMQConfig;
import com.cmc.auth.entity.User;
import com.cmc.auth.repository.UserRepository;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth/sync")
public class SyncController {

    private final UserRepository userRepository;
    private final RabbitTemplate rabbitTemplate;

    public SyncController(UserRepository userRepository, RabbitTemplate rabbitTemplate) {
        this.userRepository = userRepository;
        this.rabbitTemplate = rabbitTemplate;
    }

    @PostMapping("/{username}")
    public ResponseEntity<String> manualSync(@PathVariable String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));

        Map<String, Object> event = new HashMap<>();
        
        // 👇 [SỬA LỖI TẠI ĐÂY] Thêm key "auth_id" để khớp với UserSyncListener
        event.put("auth_id", user.getId()); // Quan trọng nhất!
        
        // Các key phụ (giữ lại để tương thích nếu cần)
        event.put("id", user.getId());       
        event.put("authId", user.getId());   
        
        event.put("username", user.getUsername());
        event.put("fullName", user.getFullName());
        event.put("email", user.getUsername());
        
        event.put("isActive", user.isActive()); 
        event.put("status", user.isActive() ? "ACTIVE" : "INACTIVE");

        event.put("roles", user.getRoles().stream()
                .map(Enum::name)
                .collect(Collectors.toSet()));

        rabbitTemplate.convertAndSend(RabbitMQConfig.EXCHANGE_NAME, RabbitMQConfig.ROUTING_KEY, event);

        return ResponseEntity.ok("Đã gửi Sync (kèm key 'auth_id') cho user: " + username);
    }
}