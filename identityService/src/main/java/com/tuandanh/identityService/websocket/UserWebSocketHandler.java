package com.tuandanh.identityService.websocket;

import com.tuandanh.identityService.entity.User;
import com.tuandanh.identityService.repository.UserRepository;
import com.tuandanh.identityService.service.redis.RedisService;
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

    private final RedisService redisService;
    private final UserRepository userRepository;
    private final Key jwtKey;

    public UserWebSocketHandler(@Value("${jwt.signerKey}") String signerKey,
                                RedisService redisService,
                                UserRepository userRepository) {
        this.redisService = redisService;
        this.userRepository = userRepository;
        this.jwtKey = Keys.hmacShaKeyFor(signerKey.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        String token = getQueryParam(session, "token");
        String userId = validateTokenAndGetUserId(token);

        if (userId == null) {
            log.warn("Unauthorized WebSocket connection attempt. Token: {}", token);
            session.close(CloseStatus.NOT_ACCEPTABLE);
            return;
        }

        // Set user online using RedisService
        redisService.setOnlineUser(userId);
        log.info("User {} connected via WebSocket.", userId);
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        String token = getQueryParam(session, "token");
        String userId = validateTokenAndGetUserId(token);

        if (userId != null) {
            redisService.removeOnlineUser(userId);
            log.info("User {} disconnected from WebSocket.", userId);
        } else {
            log.warn("Failed to extract user ID on WebSocket disconnection. Token: {}", token);
        }
    }

    /**
     * Extract query parameter from WebSocket URI.
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
     * Validate JWT token and retrieve associated user ID from the database.
     */
    private String validateTokenAndGetUserId(String token) {
        if (token == null) {
            log.warn("No token provided for WebSocket connection.");
            return null;
        }

        try {
            // Parse JWT and get claims
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(jwtKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject();
            if (username == null) {
                log.warn("Token does not contain a valid subject (username).");
                return null;
            }

            // Query user from DB
            Optional<User> optionalUser = userRepository.findByUsername(username);
            return optionalUser.map(User::getId).orElse(null);

        } catch (Exception e) {
            log.error("Failed to validate JWT token: {}", e.getMessage(), e);
            return null;
        }
    }
}

