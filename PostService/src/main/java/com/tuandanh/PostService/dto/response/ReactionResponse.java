package com.tuandanh.PostService.dto.response;

import com.tuandanh.PostService.enums.ReactionType;
import jakarta.annotation.Nullable;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class ReactionResponse {
    String id;
    String postId;
    String commentId;
    ReactionType reactionType;
    String profileId;
    LocalDateTime createdAt;
    LocalDateTime updatedAt;
    String action;
}

