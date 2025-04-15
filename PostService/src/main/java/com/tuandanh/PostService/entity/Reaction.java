package com.tuandanh.PostService.entity;

import com.tuandanh.PostService.enums.ReactionType;
import jakarta.annotation.Nullable;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.MongoId;

import java.time.LocalDateTime;

@Document(collection = "reactions")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class Reaction {
    @MongoId
    String id;
    String postId;
    @Nullable
    String commentId;
    ReactionType reactionType;
    String profileId;
    LocalDateTime createdAt;
    LocalDateTime updatedAt;
}
