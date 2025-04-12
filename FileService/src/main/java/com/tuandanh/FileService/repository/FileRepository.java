package com.tuandanh.FileService.repository;

import com.tuandanh.FileService.entity.File;
import com.tuandanh.FileService.enums.FileType;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FileRepository extends MongoRepository<File,String> {
    List<File> findByProfileId(String profileId);
    List<File> findByProfileIdAndFileType(String profileId, FileType fileType);
    List<File> findByPostId(String postId);
    void deleteByFileUrl(String fileUrl);
    void deleteAllByFileUrlIn(List<String> fileUrls);
}
