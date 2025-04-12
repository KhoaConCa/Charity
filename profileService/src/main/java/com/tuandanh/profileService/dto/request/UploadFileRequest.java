package com.tuandanh.profileService.dto.request;


import com.tuandanh.profileService.enums.FileType;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UploadFileRequest {
    String profileId;
    FileType fileType;
}
