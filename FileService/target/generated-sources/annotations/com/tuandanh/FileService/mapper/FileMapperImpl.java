package com.tuandanh.FileService.mapper;

import com.tuandanh.FileService.dto.response.FileResponse;
import com.tuandanh.FileService.entity.File;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    comments = "version: 1.5.5.Final, compiler: Eclipse JDT (IDE) 3.42.0.z20250331-1358, environment: Java 21.0.6 (Eclipse Adoptium)"
)
@Component
public class FileMapperImpl implements FileMapper {

    @Override
    public FileResponse toFileResponse(File file) {
        if ( file == null ) {
            return null;
        }

        FileResponse.FileResponseBuilder fileResponse = FileResponse.builder();

        fileResponse.createdAt( file.getCreatedAt() );
        fileResponse.fileName( file.getFileName() );
        fileResponse.fileType( file.getFileType() );
        fileResponse.fileUrl( file.getFileUrl() );
        fileResponse.id( file.getId() );
        fileResponse.postId( file.getPostId() );
        fileResponse.profileId( file.getProfileId() );
        fileResponse.updatedAt( file.getUpdatedAt() );

        return fileResponse.build();
    }
}
