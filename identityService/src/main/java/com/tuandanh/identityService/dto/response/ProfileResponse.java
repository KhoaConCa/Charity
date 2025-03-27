package com.tuandanh.identityService.dto.response;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class ProfileResponse {
    String profileId;
    String userId;
    String username;
    String firstName;
    String lastName;
    String avatarUrl;
    String location;
    LocalDateTime createdAt;
    LocalDateTime updatedAt;
    boolean isActive;
}