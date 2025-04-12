package com.tuandanh.FileService.mapper;

import com.tuandanh.FileService.dto.response.FileResponse;
import com.tuandanh.FileService.entity.File;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface FileMapper {
    FileResponse toFileResponse(File file);
}
