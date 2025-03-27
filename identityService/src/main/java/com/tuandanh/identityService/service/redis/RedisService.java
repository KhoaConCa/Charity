package com.tuandanh.identityService.service.redis;

import com.tuandanh.identityService.enums.TokenType;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class RedisService {

    StringRedisTemplate redisTemplate;

    private static final Duration ONLINE_USER_EXPIRATION = Duration.ofMinutes(10); // Online user TTL
    private static final int MAX_OTP_ATTEMPTS = 5; // Tối đa 5 lần nhập sai
    private static final String OTP_ATTEMPT_KEY = "OTP_ATTEMPT:";
    private static final String OTP_RATE_LIMIT_KEY = "OTP_RATE_LIMIT:";
    private static final String OTP_REQUEST_COUNT_KEY = "OTP_REQUEST_COUNT:";


    // ---------------------- Generic Token Methods ----------------------

    public void storeData(String key, String value, Duration ttl) {
        redisTemplate.opsForValue().set(key, value, ttl);
    }

    public String getData(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    public void deleteData(String key) {
        redisTemplate.delete(key);
    }

    public boolean exists(String key) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    // ---------------------- Token/OTP/Email Verify Wrapper ----------------------

    public void storeToken(String token, String value, TokenType type) {
        String key = buildKey(token, type);
        storeData(key, value, type.getTtl());
    }

    public String getValueByToken(String token, TokenType type) {
        String key = buildKey(token, type);
        return getData(key);
    }

    public void deleteToken(String token, TokenType type) {
        String key = buildKey(token, type);
        deleteData(key);
    }

    public boolean existsToken(String token, TokenType type) {
        String key = buildKey(token, type);
        return exists(key);
    }

    private String buildKey(String token, TokenType type) {
        return type.name() + ":" + token;
    }

    // ---------------------- OTP Rate Limiting Methods ----------------------

    /**
     * Kiểm tra xem user có gửi OTP trong vòng 30 giây gần đây không.
     * @param email Email của user.
     * @return true nếu user đã gửi OTP gần đây.
     */
    public boolean isOtpRateLimited(String email) {
        String key = OTP_RATE_LIMIT_KEY + email;
        return exists(key);
    }

    /**
     * Đánh dấu rằng user vừa gửi OTP, hạn chế gửi tiếp trong 30 giây.
     * @param email Email của user.
     */
    public void setOtpRateLimit(String email) {
        String key = OTP_RATE_LIMIT_KEY + email;
        storeData(key, "1", Duration.ofSeconds(30)); // Chặn gửi OTP trong 30 giây
    }

    /**
     * Kiểm tra xem user có gửi OTP quá 5 lần trong 10 phút không.
     * @param email Email của user.
     * @return true nếu user đã gửi quá số lần cho phép.
     */
    public boolean isOtpRequestLimitExceeded(String email) {
        String key = OTP_REQUEST_COUNT_KEY + email;
        String countStr = redisTemplate.opsForValue().get(key);
        int count = countStr != null ? Integer.parseInt(countStr) : 0;
        return count >= 5;
    }

    /**
     * Tăng số lần gửi OTP của user, giới hạn trong 10 phút.
     * @param email Email của user.
     */
    public void increaseOtpRequestCount(String email) {
        String key = OTP_REQUEST_COUNT_KEY + email;
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1) {
            redisTemplate.expire(key, 10, TimeUnit.MINUTES); // Đặt TTL 10 phút
        }
    }

    // ---------------------- OTP Attempt Methods ----------------------

    public boolean isOtpAttemptExceeded(String email) {
        String key = OTP_ATTEMPT_KEY + email;
        String attemptsStr = redisTemplate.opsForValue().get(key);
        int attempts = attemptsStr != null ? Integer.parseInt(attemptsStr) : 0;
        return attempts >= MAX_OTP_ATTEMPTS;
    }

    public void increaseOtpAttempt(String email) {
        String key = OTP_ATTEMPT_KEY + email;
        Long attempts = redisTemplate.opsForValue().increment(key);
        if (attempts != null && attempts == 1) {
            redisTemplate.expire(key, Duration.ofMinutes(10)); // Cùng thời gian sống với OTP
        }
    }

    public void resetOtpAttempts(String email) {
        String key = OTP_ATTEMPT_KEY + email;
        redisTemplate.delete(key);
    }



    // ---------------------- Online User Methods ----------------------

    public void setOnlineUser(String userId) {
        storeData(getOnlineUserKey(userId), "true", ONLINE_USER_EXPIRATION);
    }

    public void removeOnlineUser(String userId) {
        deleteData(getOnlineUserKey(userId));
    }

    public boolean isUserOnline(String userId) {
        return exists(getOnlineUserKey(userId));
    }

    private String getOnlineUserKey(String userId) {
        return "ONLINE_USER_" + userId;
    }
}


