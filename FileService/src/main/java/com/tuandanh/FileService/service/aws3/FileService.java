package com.tuandanh.FileService.service.aws3;

import com.tuandanh.FileService.dto.request.BatchUploadUrlRequest;
import com.tuandanh.FileService.dto.request.FileTypeRequest;
import com.tuandanh.FileService.dto.response.FileResponse;
import com.tuandanh.FileService.dto.response.PresignedUploadResponse;
import com.tuandanh.FileService.entity.File;
import com.tuandanh.FileService.enums.FileType;
import com.tuandanh.FileService.mapper.FileMapper;
import com.tuandanh.FileService.repository.FileRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PresignedPutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class FileService {

    private final S3Client s3Client;
    private final S3Presigner s3Presigner;
    private final String bucketName;
    private final FileRepository fileRepository;
    private final FileMapper fileMapper;
    @Value("${cdn.domain}")
    private String cdnDomain;

    public FileService(@Value("${aws3.access_key}") String accessKey,
                       @Value("${aws3.secret_key}") String secretKey,
                       @Value("${aws3.bucket_name}") String bucketName,
                       @Value("${aws3.region}") String region,
                       FileRepository fileRepository, FileMapper fileMapper) {

        this.bucketName = bucketName;
        this.fileRepository = fileRepository;
        this.fileMapper = fileMapper;

        AwsBasicCredentials awsCreds = AwsBasicCredentials.create(accessKey, secretKey);
        StaticCredentialsProvider credsProvider = StaticCredentialsProvider.create(awsCreds);
        this.s3Client = S3Client.builder()
                .region(Region.of(region))
                .credentialsProvider(StaticCredentialsProvider.create(awsCreds))
                .build();

        this.s3Presigner = S3Presigner.builder()
                .region(Region.of(region))
                .credentialsProvider(credsProvider)
                .build();
    }

    public List<PresignedUploadResponse> generateBatchUploadUrls(BatchUploadUrlRequest request) {
        List<PresignedUploadResponse> result = new ArrayList<>();

        for (String originalFileName : request.getFileName()) {
            String fileName = UUID.randomUUID() + "_" + originalFileName;
            String objectKey = fileName;

            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(objectKey)
                    .contentType("image/jpeg") // Hoặc param nếu cần
                    .build();


            PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
                    .putObjectRequest(putObjectRequest)
                    .signatureDuration(Duration.ofMinutes(10))
                    .build();

            PresignedPutObjectRequest presignedRequest = s3Presigner.presignPutObject(presignRequest);

            result.add(PresignedUploadResponse.builder()
                    .fileName(fileName)
                    .uploadUrl(presignedRequest.url().toString())
                    .finalUrl("https://" + bucketName + ".s3.amazonaws.com/" + fileName)
                    .build()
            );
        }

        return result;
    }



    public String generatePresignedUploadUrl(String fileName, String contentType) {
        PutObjectRequest objectRequest = PutObjectRequest.builder()
                .bucket(bucketName)
                .key(fileName)
                .contentType(contentType)
                .build();

        PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
                .signatureDuration(Duration.ofMinutes(10))  // Thời gian URL có hiệu lực
                .putObjectRequest(objectRequest)
                .build();

        PresignedPutObjectRequest presignedRequest = s3Presigner.presignPutObject(presignRequest);
        return presignedRequest.url().toString();
    }

    public String uploadFileVersion1(MultipartFile file, String profileId, FileType fileType) throws IOException {
        String fileName = UUID.randomUUID().toString() + "_" + file.getOriginalFilename();
        String fileUrl = "https://" + cdnDomain + "/" + fileName;

        // Upload file lên S3
        s3Client.putObject(
                PutObjectRequest.builder()
                        .bucket(bucketName)
                        .key(fileName)
                        .contentType(file.getContentType())
                        .build(),
                RequestBody.fromBytes(file.getBytes())
        );



        // Lưu metadata vào database
        File avatar = File.builder()
                .profileId(profileId)
                .fileName(fileName)
                .fileUrl(fileUrl)
                .fileType(fileType)
                .createdAt(Instant.now().toString())
                .updatedAt(Instant.now().toString())
                .build();


        fileRepository.save(avatar);

        return avatar.getFileUrl();
    }


    public String uploadFile(MultipartFile file, String profileId, FileType fileType) throws IOException {
        String fileName = UUID.randomUUID().toString() + "_" + file.getOriginalFilename();
        String fileUrl = "https://" + bucketName + ".s3.amazonaws.com/" + fileName;

        // Upload file lên S3
        s3Client.putObject(
                PutObjectRequest.builder()
                        .bucket(bucketName)
                        .key(fileName)
                        .contentType(file.getContentType())
                        .build(),
                RequestBody.fromBytes(file.getBytes())
        );



        // Lưu metadata vào database
        File avatar = File.builder()
                .profileId(profileId)
                .fileName(fileName)
                .fileUrl(fileUrl)
                .fileType(fileType)
                .createdAt(Instant.now().toString())
                .updatedAt(Instant.now().toString())
                .build();


        fileRepository.save(avatar);

        return avatar.getFileUrl();
    }

    /**
     * Upload nhiều file lên S3
     * @param files Danh sách các file cần tải lên
     * @param profileId ID của người dùng
     * @param fileType Loại file
     * @return Danh sách URL của các file đã upload
     * @throws IOException Nếu có lỗi khi upload file
     */
    public List<String> uploadFiles(List<MultipartFile> files, String profileId, FileType fileType) throws IOException {
        List<String> fileUrls = new ArrayList<>();

        // Lặp qua từng file và upload lên S3
        for (MultipartFile file : files) {
            String fileUrl = uploadFile(file, profileId, fileType); // Gọi lại hàm uploadFile cho mỗi file
            fileUrls.add(fileUrl);
        }

        return fileUrls;
    }

    /**
     * Xóa file theo URL từ S3
     * @param fileUrl URL file cần xóa
     */

    public void deleteFile(String fileUrl) {
        String fileName = fileUrl.substring(fileUrl.lastIndexOf("/") + 1);

        s3Client.deleteObject(builder -> builder
                .bucket(bucketName)
                .key(fileName)
                .build());
        fileRepository.deleteByFileUrl(fileUrl);
    }

    /**
     * Xóa nhiều file khỏi S3 và xóa metadata trong database
     *
     * @param fileUrls Danh sách URL file cần xóa
     */
    public void deleteFiles(List<String> fileUrls) {
        if (fileUrls == null || fileUrls.isEmpty()) return;

        for (String fileUrl : fileUrls) {
            // Lấy fileName từ URL
            String fileName = fileUrl.substring(fileUrl.lastIndexOf("/") + 1);

            // Xóa trên S3
            s3Client.deleteObject(builder -> builder
                    .bucket(bucketName)
                    .key(fileName)
                    .build());

        }

        fileRepository.deleteAllByFileUrlIn(fileUrls);
    }


    public List<FileResponse> getUserFiles(String profileId) {
        return fileRepository.findByProfileId(profileId).stream()
                .map(fileMapper::toFileResponse)
                .toList();
    }

    public List<FileResponse> getUserDetailsTypeFiles(String profileId, FileTypeRequest fileTypeRequest) {
        return fileRepository.findByProfileIdAndFileType(profileId, fileTypeRequest.getFileType()).stream()
                .map(fileMapper::toFileResponse)
                .toList();

    }

    public List<FileResponse> getUserFilesByPostId(String postId){
        return fileRepository.findByPostId(postId).stream()
                .map(fileMapper::toFileResponse)
                .toList();
    }

}
