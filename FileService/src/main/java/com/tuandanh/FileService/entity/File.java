package com.tuandanh.FileService.entity;

import com.tuandanh.FileService.enums.FileType;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.MongoId;

@Document(collection = "files")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class File {
    @MongoId
    String id;

    String profileId; // ID của user sở hữu file
    String postId;
    String fileName;
    String fileUrl;
    FileType fileType; // AVATAR, POST_MEDIA

    String createdAt;
    String updatedAt;
}
