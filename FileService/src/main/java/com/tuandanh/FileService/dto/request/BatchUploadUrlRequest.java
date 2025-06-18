package com.tuandanh.FileService.dto.request;

import com.tuandanh.FileService.enums.FileType;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class BatchUploadUrlRequest {
    String profileId;
    List<String> fileName;
    FileType fileType;
}
