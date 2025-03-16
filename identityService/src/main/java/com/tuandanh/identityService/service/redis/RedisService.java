package com.tuandanh.identityService.service.redis;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class RedisTokenService {
    StringRedisTemplate redisTemplate;

    private final static Duration TOKEN_EXPIRATION = Duration.ofMinutes(30); // Token valid for 30 minutes

    public void storeToken(String token, String email) {
        redisTemplate.opsForValue().set(token, email, TOKEN_EXPIRATION);
    }

    public String getEmailByToken(String token) {
        return redisTemplate.opsForValue().get(token);
    }

    public void deleteToken(String token) {
        redisTemplate.delete(token);
    }
}


