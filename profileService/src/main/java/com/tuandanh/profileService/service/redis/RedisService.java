package com.tuandanh.profileService.service.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class RedisService {
    private static final String PROFILE_KEY_PREFIX = "activeProfile:";
    private final RedisTemplate<String, String> redisTemplate;

    public void setActiveProfile(String userId, String profileId) {
        redisTemplate.opsForValue().set(PROFILE_KEY_PREFIX + userId, profileId, Duration.ofHours(2));
    }

    public String getActiveProfile(String userId) {
        return redisTemplate.opsForValue().get(PROFILE_KEY_PREFIX + userId);
    }
}

