package com.tuandanh.profileService.entity;

import com.tuandanh.profileService.enums.FriendStatus;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.data.neo4j.core.schema.GeneratedValue;
import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;
import org.springframework.data.neo4j.core.schema.Property;
import org.springframework.data.neo4j.core.support.UUIDStringGenerator;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Node("FriendshipRequest")
public class Friendship {
    @Id
    @GeneratedValue(generatorClass = UUIDStringGenerator.class)
    String id;

    @Property("senderId")
    String senderId;

    @Property("receiverId")
    String receiverId;

    @Property("status")
    FriendStatus status;
}
