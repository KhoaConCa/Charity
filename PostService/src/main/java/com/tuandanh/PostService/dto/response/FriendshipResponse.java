package com.tuandanh.PostService.dto.response;

import com.tuandanh.PostService.enums.FriendStatus;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class FriendshipResponse {
    String id;
    String senderId;
    String receiverId;
    FriendStatus status;
}
