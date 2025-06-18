package com.tuandanh.event.dto;

import com.tuandanh.FileService.enums.FileType;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class FileMetadataConfirmRequest {
    String fileName;
    String fileUrl;
    FileType fileType;
    String profileId;
    Long fileSize;
    String contentType;
    LocalDateTime uploadedAt;
}
