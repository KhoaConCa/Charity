package com.tuandanh.PostService.entity;

import com.tuandanh.PostService.enums.Privacy;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.MongoId;
import org.springframework.data.geo.Point;

import java.time.LocalDateTime;
import java.util.List;

@Document(collection = "posts")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class Post {
    @MongoId
    String id;
    String profileId;
    String content;
    List<String> fileIds;
    List<String> tags;
    Privacy privacy;
    Point point;
    LocalDateTime donationStartTime;
    LocalDateTime donationEndTime;
    LocalDateTime createdAt;
    LocalDateTime updatedAt;
}
