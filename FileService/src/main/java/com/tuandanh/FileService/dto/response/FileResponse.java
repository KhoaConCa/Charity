package com.tuandanh.FileService.dto.response;

import com.tuandanh.FileService.enums.FileType;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class FileResponse {
    String id;

    String profileId; // ID của user sở hữu file
    String postId;
    String fileName;
    String fileUrl;
    FileType fileType; // AVATAR, POST_MEDIA

    String createdAt;
    String updatedAt;
}
