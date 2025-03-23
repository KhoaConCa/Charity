package com.tuandanh.identityService.enums;

import java.time.Duration;

public enum TokenType {
    RESET_PASSWORD(Duration.ofMinutes(30)),
    VERIFY_EMAIL(Duration.ofMinutes(15)),
    TWO_FACTOR(Duration.ofMinutes(5)); // thời gian sống của OTP

    private final Duration ttl;

    TokenType(Duration ttl) {
        this.ttl = ttl;
    }

    public Duration getTtl() {
        return ttl;
    }
}

