package com.tuandanh.identityService.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserOnlineStatusResponse {
    private String userId;
    private String username;
    private boolean isActive;
    private LocalDateTime lastActiveAt;
}
