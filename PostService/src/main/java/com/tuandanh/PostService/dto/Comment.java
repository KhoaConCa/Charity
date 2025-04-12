package com.tuandanh.PostService.dto;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class Comment {
    String profileId;
    String content;
    String createdAt;
    String updatedAt;
    List<Comment> replies;
}
