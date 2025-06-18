package com.tuandanh.FileService.service;


import com.tuandanh.FileService.entity.File;
import com.tuandanh.FileService.enums.FileType;
import com.tuandanh.FileService.repository.FileRepository;
import com.tuandanh.event.dto.FileMetadataConfirmRequest;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.format.DateTimeParseException;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class FileMetaConsumer {
    FileRepository fileRepository;

    @KafkaListener(topics = "media.file.metadata", groupId = "file-service-group", containerFactory = "kafkaListenerContainerFactory")
    public void handleFileMetadata(FileMetadataConfirmRequest event) {
        try {
            // Validate cơ bản
            if (!event.getFileUrl().contains(".s3.amazonaws.com")) {
                System.err.println(" Invalid file URL, skipping: " + event.getFileUrl());
                return;
            }

            File file = File.builder()
                    .fileName(event.getFileName())
                    .fileUrl(event.getFileUrl())
                    .profileId(event.getProfileId())
                    .fileType(event.getFileType() != null ? event.getFileType() : FileType.OTHER)
                    .createdAt(event.getUploadedAt() != null
                            ? event.getUploadedAt().toString()
                            : Instant.now().toString())
                    .updatedAt(Instant.now().toString())
                    .build();

            fileRepository.save(file);
            log.info(" File metadata saved: " + file.getFileUrl());

        } catch (DateTimeParseException e) {
           log.error("Failed to parse date from event: " + event);
        } catch (Exception e) {
            log.error("Error saving file metadata: " + e.getMessage());
        }
    }
}
