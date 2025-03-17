package com.tuandanh.identityService.dto.response;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserResponse {
    String id;
    String username;
    String firstName;
    String lastName;
    LocalDate dob;
    String email;
    boolean blocked; // Shows if user is blocked
//    LocalDateTime lastActiveAt; // Shows when the user was last active
    String provider;
    Set<RoleResponse> roles;
}
