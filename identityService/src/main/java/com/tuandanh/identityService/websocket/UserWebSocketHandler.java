package com.tuandanh.identityService.websocket;

import com.tuandanh.identityService.entity.User;
import com.tuandanh.identityService.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Component
@Slf4j

public class UserWebSocketHandler extends TextWebSocketHandler {

    private final RedisTemplate<String, Object> redisTemplate;
    private final Key jwtKey;
    private final UserRepository userRepository;

    public UserWebSocketHandler(RedisTemplate<String, Object> redisTemplate,
                                @Value("${jwt.signerKey}") String signerKey, UserRepository userRepository) {
        log.error("SAIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII");
        this.redisTemplate = redisTemplate;
        this.jwtKey = Keys.hmacShaKeyFor(signerKey.getBytes(StandardCharsets.UTF_8));
        this.userRepository = userRepository;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        String token = getQueryParam(session, "token");
        String userId = validateTokenAndGetUserId(token);

        if (userId == null) {
            System.out.println("Unauthorized WebSocket connection attempt.");
            session.close(CloseStatus.NOT_ACCEPTABLE);
            return;
        }

        // Set status online in Redis
        redisTemplate.opsForValue().set("ONLINE_USER_" + userId, "true", Duration.ofMinutes(10));
        System.out.println("User " + userId + " connected");
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        String token = getQueryParam(session, "token");
        String userId = validateTokenAndGetUserId(token);

        if (userId != null) {
            redisTemplate.delete("ONLINE_USER_" + userId);
            System.out.println("User " + userId + " disconnected");
        }
    }

    /**
     * Parse query parameters safely.
     */
    private String getQueryParam(WebSocketSession session, String paramName) {
        URI uri = session.getUri();
        if (uri == null || uri.getQuery() == null) {
            return null;
        }

        String[] pairs = uri.getQuery().split("&");
        Map<String, String> queryPairs = new HashMap<>();
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            if (idx > 0 && idx < pair.length() - 1) {
                String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
                String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                queryPairs.put(key, value);
            }
        }

        return queryPairs.get(paramName);
    }

    /**
     * Validate JWT token and extract userId.
     */
    private String validateTokenAndGetUserId(String token) {
        try {
            if (token == null) {
                return null;
            }

            // Bước 1: Parse token lấy username
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(jwtKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject(); // Đây là username
            if (username == null) {
                return null;
            }

            // Bước 2: Truy vấn DB để lấy userId từ username
            Optional<User> optionalUser = userRepository.findByUsername(username);
            if (optionalUser.isPresent()) {
                User user = optionalUser.get();
                return user.getId();
            } else {
                return null;
            }

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}

