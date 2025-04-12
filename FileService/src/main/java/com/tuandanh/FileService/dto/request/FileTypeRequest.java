package com.tuandanh.FileService.dto.request;

import com.tuandanh.FileService.enums.FileType;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class FileTypeRequest {
    FileType fileType;
}
