package com.tuandanh.PostService.dto.response;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class CommentResponse {
    String id;
    String profileId;
    String postId;
    String parentId;
    String content;
    List<String> fileIds;
    LocalDateTime createdAt;
    LocalDateTime updatedAt;
}
