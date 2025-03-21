package com.tuandanh.profileService.entity;

import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.context.annotation.Profile;
import org.springframework.data.neo4j.core.schema.*;
import org.springframework.data.neo4j.core.support.UUIDStringGenerator;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Node("User_Profile")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserProfile {
    @Id
    @GeneratedValue(generatorClass = UUIDStringGenerator.class)
    String profileId;

    @Property("userId")
    String userId;
    String username;
    String firstName;
    String lastName;
    String avatarUrl;
    String location;
    LocalDateTime createdAt;
    LocalDateTime updatedAt;
    boolean isActive;

    @Relationship(type = "FOLLOWS", direction = Relationship.Direction.OUTGOING)
    Set<Profile> following = new HashSet<>();

}
