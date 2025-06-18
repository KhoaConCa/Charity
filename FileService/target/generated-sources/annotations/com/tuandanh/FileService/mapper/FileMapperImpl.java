package com.tuandanh.FileService.mapper;

import com.tuandanh.FileService.dto.response.FileResponse;
import com.tuandanh.FileService.entity.File;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    comments = "version: 1.5.5.Final, compiler: javac, environment: Java 21.0.3 (Oracle Corporation)"
)
@Component
public class FileMapperImpl implements FileMapper {

    @Override
    public FileResponse toFileResponse(File file) {
        if ( file == null ) {
            return null;
        }

        FileResponse.FileResponseBuilder fileResponse = FileResponse.builder();

        fileResponse.id( file.getId() );
        fileResponse.profileId( file.getProfileId() );
        fileResponse.postId( file.getPostId() );
        fileResponse.fileName( file.getFileName() );
        fileResponse.fileUrl( file.getFileUrl() );
        fileResponse.fileType( file.getFileType() );
        fileResponse.createdAt( file.getCreatedAt() );
        fileResponse.updatedAt( file.getUpdatedAt() );

        return fileResponse.build();
    }
}
