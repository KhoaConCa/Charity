package com.tuandanh.PostService.dto.response;

import com.tuandanh.PostService.dto.Comment;
import com.tuandanh.PostService.dto.Reaction;
import com.tuandanh.PostService.enums.Privacy;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.data.geo.Point;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class PostResponse {
    String profileId;
    String content;
    List<String> fileIds;
    List<Reaction> reactions;
    List<String> tags;
    Privacy privacy;
    Point point;
    List<Comment> comments;
    LocalDateTime createdAt;
    LocalDateTime updatedAt;
}
