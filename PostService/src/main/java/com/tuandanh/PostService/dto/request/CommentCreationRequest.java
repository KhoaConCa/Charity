package com.tuandanh.PostService.dto.request;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class CommentCreationRequest {
    String postId;
    String parentId;
    String content;
    List<String> tags;

    @Builder.Default
    LocalDateTime createdAt = LocalDateTime.now();
}
