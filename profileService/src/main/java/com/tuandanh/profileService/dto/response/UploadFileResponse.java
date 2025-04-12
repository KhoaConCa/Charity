package com.tuandanh.profileService.dto.response;


import com.tuandanh.profileService.enums.FileType;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UploadFileResponse {
    String id;

    String profileId; // ID của user sở hữu file
    String fileName;
    String fileUrl;
    FileType fileType; // AVATAR, POST_MEDIA

    String createdAt;
    String updatedAt;
}
