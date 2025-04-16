package com.tuandanh.PostService.dto.request;

import com.tuandanh.PostService.enums.ReactionType;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class ReactionDeletionRequest {
    String postId;
    ReactionType reactionType;
}
