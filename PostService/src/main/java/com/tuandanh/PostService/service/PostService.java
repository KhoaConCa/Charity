package com.tuandanh.PostService.service;
import com.tuandanh.PostService.dto.ApiResponse;
import com.tuandanh.PostService.dto.PageResponse;
import com.tuandanh.PostService.dto.request.PostUpdateRequest;
import com.tuandanh.PostService.dto.response.FileResponse;
import com.tuandanh.PostService.dto.response.FriendshipResponse;
import com.tuandanh.PostService.dto.response.PostResponse;
import com.tuandanh.PostService.dto.request.PostCreationRequest;
import com.tuandanh.PostService.dto.response.ProfileResponse;
import com.tuandanh.PostService.entity.Comment;
import com.tuandanh.PostService.entity.Post;
import com.tuandanh.PostService.entity.Reaction;
import com.tuandanh.PostService.enums.*;
import com.tuandanh.PostService.exception.AppException;
import com.tuandanh.PostService.exception.ErrorCode;
import com.tuandanh.PostService.mapper.PostMapper;
import com.tuandanh.PostService.repository.CommentRepository;
import com.tuandanh.PostService.repository.PostRepository;
import com.tuandanh.PostService.repository.ReactionRepository;
import com.tuandanh.PostService.repository.httpClient.FileClient;
import com.tuandanh.PostService.repository.httpClient.UserProfileClient;
import com.tuandanh.event.dto.NotificationEvent;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class PostService {
    PostRepository postRepository;
    ReactionRepository reactionRepository;
    CommentRepository commentRepository;
    PostMapper postMapper;
    CommentService commentService;
    KafkaTemplate<String, NotificationEvent> kafkaTemplate;

    private static final String NOTIFY_TAGGED_USERS_TOPIC = "tag-notification-topic";
    private final FileClient fileClient;
    private final UserProfileClient userProfileClient;

    public PostResponse createPost(PostCreationRequest postCreationRequest,
                                   List<MultipartFile> mediaFiles,
                                   String authorization) {

        // 0. Kiểm tra tag có hợp lệ không (có nằm trong danh sách bạn bè không)
//        if (isTags(postCreationRequest.getTags(), authorization)) {
//            throw new AppException(ErrorCode.INVALID_TAGS);
//        }

        // 1. Khởi tạo bài viết (chưa set fileIds vội)
        Post post = Post.builder()
                .profileId(postCreationRequest.getProfileId())
                .content(postCreationRequest.getContent())
                .fileIds(new ArrayList<>())
                .tags(postCreationRequest.getTags())
                .privacy(postCreationRequest.getPrivacy())
                .point(postCreationRequest.getPoint())
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        // 2. Nếu có file, upload và gán vào fileIds
        if (mediaFiles != null && !mediaFiles.isEmpty()) {
            ApiResponse<List<String>> response = fileClient.uploadFiles(
                    mediaFiles,
                    postCreationRequest.getProfileId(),
                    FileType.POST_MEDIA
            );
            post.setFileIds(response.getResult());
        }

        // 4. Lưu vào DB 1 lần duy nhất
        Post savedPost = postRepository.save(post);

        // 3. Nếu public, thêm reaction mặc định
        if (postCreationRequest.getPrivacy() == Privacy.PUBLIC) {
            Reaction defaultReaction = Reaction.builder()
                    .postId(savedPost.getId())
                    .reactionType(ReactionType.LIKE)
                    .profileId(postCreationRequest.getProfileId())
                    .build();
            reactionRepository.save(defaultReaction);
        }
        Set<String> recipients = new HashSet<>(
                Optional.ofNullable(postCreationRequest.getTags()).orElse(Collections.emptyList())
        );


//        sendTagNotification(post, recipients);



        // 5. Trả về response
        return postMapper.toPostResponse(savedPost);
    }

    private void sendTagNotification(Post post, Set<String> recipients) {
        ProfileResponse profileResponse = userProfileClient.getProfile(post.getProfileId()).getResult();

        for (String recipientId : recipients) {
            NotificationEvent event = NotificationEvent.builder()
                    .chanel(CHANEL.PUSH_NOTIFICATION)
                    .recipient(recipientId)
                    .subject("Bạn đã được tag trong một bài viết")
                    .body(post.getContent())
                    .notificationType(NotificationType.TAGS)
                    .sentAt(LocalDateTime.now())
                    .param(Map.of(
                            "postId", post.getId(),
                            "senderId", post.getProfileId(),
                            "avatarUrl", profileResponse.getAvatarUrl()
                    ))
                    .build();

            kafkaTemplate.send(NOTIFY_TAGGED_USERS_TOPIC, event);
            log.info("Sent tag notification to Kafka for recipient {}: {}", recipientId, event);
        }
    }



    private boolean isTags(List<String> tags, String authorization) {
        List<FriendshipResponse> friendshipResponses = userProfileClient.getFriends(authorization).getResult();

        // Chuyển danh sách bạn bè thành tập hợp profileId để tiện kiểm tra
        Set<String> friendIds = friendshipResponses.stream()
                .map(FriendshipResponse::getSenderId)
                .collect(Collectors.toSet());

        // Kiểm tra tất cả các tag có nằm trong danh sách bạn bè không
        return !friendIds.containsAll(tags);
    }

    public PostResponse updatePost(String postId,
                                   PostUpdateRequest postUpdateRequest,
                                   List<MultipartFile> newMediaFiles,
                                   List<String> filesToRemove,
                                   String authorization) {

        // 1. Tìm bài viết
        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new AppException(ErrorCode.POST_NOT_FOUND));

        // 2. Kiểm tra quyền
        if (!post.getProfileId().equals(postUpdateRequest.getProfileId())) {
            throw new AppException(ErrorCode.UNAUTHORIZED);
        }

        // 3. Kiểm tra tag hợp lệ
//        if (isTags(postUpdateRequest.getTags(), authorization)) {
//            throw new AppException(ErrorCode.INVALID_TAGS);
//        }

        // 4. So sánh tags mới và cũ để tìm các tag mới cần gửi thông báo
        Set<String> oldTags = new HashSet<>(Optional.ofNullable(post.getTags()).orElse(List.of()));
        Set<String> newTags = new HashSet<>(Optional.ofNullable(postUpdateRequest.getTags()).orElse(List.of()));
        Set<String> addedTags = new HashSet<>(newTags);
        addedTags.removeAll(oldTags); // chỉ giữ các tag mới

        // 5. Cập nhật nội dung bài viết
        post.setContent(postUpdateRequest.getContent());
        post.setPrivacy(postUpdateRequest.getPrivacy());
        post.setTags(postUpdateRequest.getTags());
        post.setPoint(postUpdateRequest.getPoint());
        post.setUpdatedAt(LocalDateTime.now());

        // 6. Xóa file cũ nếu có chỉ định
        if (filesToRemove != null && !filesToRemove.isEmpty()) {
            filesToRemove = filesToRemove.stream()
                    .map(String::trim) // Loại bỏ khoảng trắng thừa
                    .collect(Collectors.toList());
            post.getFileIds().removeAll(filesToRemove);
            fileClient.deleteFiles(filesToRemove); // Gọi sang File Service để xóa vật lý (nếu cần)
        }

        // 7. Upload file mới nếu có
        if (newMediaFiles != null && !newMediaFiles.isEmpty()) {
            ApiResponse<List<String>> response = fileClient.uploadFiles(
                    newMediaFiles,
                    postUpdateRequest.getProfileId(),
                    FileType.POST_MEDIA
            );
            post.getFileIds().addAll(response.getResult());
        }

        // 8. Gửi thông báo cho các tag mới

//            sendTagNotification(post, addedTags);

        // 9. Lưu lại bài viết
        Post savedPost = postRepository.save(post);

        // 10. Trả về response
        return postMapper.toPostResponse(savedPost);
    }


    public void deletePost(String postId, Authentication authentication) {
        // 1. Tìm bài viết
        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new AppException(ErrorCode.POST_NOT_FOUND));

        // 2. Lấy thông tin người hiện tại
        Jwt jwt = (Jwt) authentication.getPrincipal();
        String userId = jwt.getClaim("userId");
        String activeProfileId = userProfileClient.getActiveProfile(userId).getResult();



        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));

        // 3. Kiểm tra quyền: chỉ Admin hoặc chủ bài viết mới được xóa
        if (!isAdmin && !post.getProfileId().equals(activeProfileId)) {
            throw new AppException(ErrorCode.UNAUTHORIZED);
        }

        // 4. Xóa reaction trên post
        reactionRepository.deleteByPostId(postId);

        // 5. Tìm tất cả comment liên quan đến post
        List<Comment> comments = commentRepository.findByPostId(postId);

        for (Comment comment : comments) {
            // 5.1 Xóa reactions trên comment
            reactionRepository.deleteAllByCommentId(comment.getId());
            commentService.deleteComment(comment.getId());
        }


        // 3. Nếu có file, xóa từng file khỏi S3 và xóa metadata khỏi DB
        if (post.getFileIds() != null && !post.getFileIds().isEmpty()) {
            // Lấy thông tin file từ DB
           List<FileResponse> fileResponses = fileClient.getFilesByPostId(postId).getResult();

            List<String> fileUrls = new ArrayList<>();
            for (FileResponse fileResponse : fileResponses) {
                fileUrls.add(fileResponse.getFileUrl());
            }

            // Nếu bạn không gọi xóa metadata bên trong deleteFile, thì xóa ở đây:
            fileClient.deleteFiles(fileUrls);
        }

        // 4. Xóa bài viết khỏi DB
        postRepository.delete(post);
    }

//        @PreAuthorize("hasRole('ADMIN')")
    public PageResponse<PostResponse> getAllPosts(int page, int size){
            Sort sort = Sort.by("createdAt").descending();
            Pageable pageable = PageRequest.of(page - 1, size, sort);
            var pageData = postRepository.findAll(pageable);

            return PageResponse.<PostResponse>builder()
                    .currentPage(page)
                    .pageSize(pageData.getSize())
                    .totalElements(pageData.getTotalElements())
                    .data(pageData.getContent().stream().map(postMapper::toPostResponse).toList())
                    .build();
    }


    public PageResponse<PostResponse> getAllPostsByProfileId(String profileId, int page, int size){
        Sort sort = Sort.by("createdAt").descending();
        Pageable pageable = PageRequest.of(page - 1, size, sort);
        var pageData = postRepository.findAllByProfileId(profileId, pageable);

        return PageResponse.<PostResponse>builder()
                .currentPage(page)
                .pageSize(pageData.getSize())
                .totalElements(pageData.getTotalElements())
                .data(pageData.getContent().stream().map(postMapper::toPostResponse).toList())
                .build();
    }

    public PostResponse getPostByPostId(String postId){
        return postMapper.toPostResponse(postRepository.findById(postId)
                .orElseThrow(() -> new AppException(ErrorCode.POST_NOT_FOUND)));
    }

    public PageResponse<PostResponse> getMyPosts(int page, int size, Authentication authentication){
        Jwt jwt = (Jwt) authentication.getPrincipal();
        String userId = jwt.getClaim("userId");
        String activeProfileId = userProfileClient.getActiveProfile(userId).getResult();

        Sort sort = Sort.by("createdAt").descending();
        Pageable pageable = PageRequest.of(page - 1, size, sort);
        var pageData = postRepository.findAllByProfileId(activeProfileId, pageable);

        return PageResponse.<PostResponse>builder()
                .currentPage(page)
                .pageSize(pageData.getSize())
                .totalElements(pageData.getTotalElements())
                .data(pageData.getContent().stream().map(postMapper::toPostResponse).toList())
                .build();
    }



}
