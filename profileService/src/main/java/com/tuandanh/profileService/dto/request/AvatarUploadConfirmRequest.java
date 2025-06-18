package com.tuandanh.profileService.dto.request;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class AvatarUploadConfirmRequest {
    String fileName;
    String fileUrl;
    String contentType;
    Long fileSize;
}
