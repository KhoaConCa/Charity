package com.tuandanh.profileService.dto.response;

import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.data.neo4j.core.schema.GeneratedValue;
import org.springframework.data.neo4j.core.schema.Property;
import org.springframework.data.neo4j.core.support.UUIDStringGenerator;

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
