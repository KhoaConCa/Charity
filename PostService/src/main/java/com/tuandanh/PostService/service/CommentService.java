package com.tuandanh.PostService.service;

import com.tuandanh.PostService.dto.ApiResponse;
import com.tuandanh.PostService.dto.PageResponse;
import com.tuandanh.PostService.dto.request.CommentCreationRequest;
import com.tuandanh.PostService.dto.request.CommentUpdateRequest;
import com.tuandanh.PostService.dto.response.CommentResponse;
import com.tuandanh.PostService.dto.response.ReactionResponse;
import com.tuandanh.PostService.entity.Comment;
import com.tuandanh.PostService.enums.FileType;
import com.tuandanh.PostService.exception.AppException;
import com.tuandanh.PostService.exception.ErrorCode;
import com.tuandanh.PostService.mapper.CommentMapper;
import com.tuandanh.PostService.repository.CommentRepository;
import com.tuandanh.PostService.repository.httpClient.FileClient;
import com.tuandanh.PostService.repository.httpClient.UserProfileClient;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class CommentService {
    CommentRepository commentRepository;
    UserProfileClient userProfileClient;
    CommentMapper commentMapper;
    FileClient fileClient;


    public CommentResponse createComment(CommentCreationRequest commentCreationRequest
            , List<MultipartFile> mediaFiles, Authentication authentication){
        String profileId = getProfileIdFromAuthentication(authentication);

        Comment comment = commentMapper.toComment(commentCreationRequest);
        comment.setProfileId(profileId);
        // 2. Nếu có file, upload và gán vào fileIds
        if (mediaFiles != null && !mediaFiles.isEmpty()) {
            ApiResponse<List<String>> response = fileClient.uploadFiles(
                    mediaFiles,
                    profileId,
                    FileType.COMMENT_MEDIA
            );
            comment.setFileIds(response.getResult());
        }

        return commentMapper.toCommentResponse(commentRepository.save(comment));
    }

    public CommentResponse updateComment(CommentUpdateRequest commentUpdateRequest,
                                         List<MultipartFile> mediaFiles, String commentId,
                                         List<String> filesToRemove){
        Comment comment = commentRepository.findById(commentId).orElseThrow(
                () -> new AppException(ErrorCode.COMMENT_NOT_FOUND)
        );

        // 4. So sánh tags mới và cũ để tìm các tag mới cần gửi thông báo
        Set<String> oldTags = new HashSet<>(Optional.ofNullable(comment.getTags()).orElse(List.of()));
        Set<String> newTags = new HashSet<>(Optional.ofNullable(commentUpdateRequest.getTags()).orElse(List.of()));
        Set<String> addedTags = new HashSet<>(newTags);
        addedTags.removeAll(oldTags); // chỉ giữ các tag mới

        comment.setContent(commentUpdateRequest.getContent());
        comment.setTags(commentUpdateRequest.getTags());
        comment.setUpdatedAt(LocalDateTime.now());

        // 6. Xóa file cũ nếu có chỉ định
        if (filesToRemove != null && !filesToRemove.isEmpty()) {
            filesToRemove = filesToRemove.stream()
                    .map(String::trim) // Loại bỏ khoảng trắng thừa
                    .collect(Collectors.toList());
            comment.getFileIds().removeAll(filesToRemove);
            fileClient.deleteFiles(filesToRemove); // Gọi sang File Service để xóa vật lý (nếu cần)
        }

        // 7. Upload file mới nếu có
        if (mediaFiles != null && !mediaFiles.isEmpty()) {
            ApiResponse<List<String>> response = fileClient.uploadFiles(
                    mediaFiles,
                    comment.getProfileId(),
                    FileType.COMMENT_MEDIA
            );
            comment.getFileIds().addAll(response.getResult());
        }

        // 8. Gửi thông báo cho các tag mới

//            sendTagNotification(post, addedTags);

        return commentMapper.toCommentResponse(commentRepository.save(comment));
    }

    public void deleteComment(String commentId) {
        if(!commentRepository.existsById(commentId)){
            throw new AppException(ErrorCode.COMMENT_NOT_FOUND);
        }

        // 2. Xoá đệ quy tất cả các reply của comment này
        deleteRepliesRecursively(commentId);

        // 3. Xoá comment gốc
        commentRepository.deleteById(commentId);
    }

    private void deleteRepliesRecursively(String parentId) {
        List<Comment> replies = commentRepository.findAllByParentId(parentId);

        for (Comment reply : replies) {
            // Xoá các reply lồng nhau
            deleteRepliesRecursively(reply.getId());
            // Xoá reply hiện tại
            commentRepository.deleteById(reply.getId());
        }
    }

    public void deleteReply(String replyId) {
        // 1. Tìm reply (comment con)
        Comment reply = commentRepository.findById(replyId)
                .orElseThrow(() -> new AppException(ErrorCode.COMMENT_NOT_FOUND));

        // 2. Xoá reply
        // Nếu có file đính kèm, bạn cũng có thể xoá file vật lý (nếu cần)
        if (reply.getFileIds() != null && !reply.getFileIds().isEmpty()) {
            fileClient.deleteFiles(reply.getFileIds());
        }

        commentRepository.deleteById(replyId);
    }



    public PageResponse<CommentResponse> getCommentsByPost(String postId, int page, int size){
        Sort sort = Sort.by("createdAt").descending();
        Pageable pageable = PageRequest.of(page - 1, size, sort);
        var pageData = commentRepository.findAllByPostId(postId, pageable);

        return PageResponse.<CommentResponse>builder()
                .currentPage(page)
                .pageSize(pageData.getSize())
                .totalElements(pageData.getTotalElements())
                .data(pageData.getContent().stream().map(commentMapper::toCommentResponse).toList())
                .build();
    }

    public PageResponse<CommentResponse> getRepliesByComment(String parentId, int page, int size){
        Sort sort = Sort.by("createdAt").descending();
        Pageable pageable = PageRequest.of(page - 1, size, sort);
        var pageData = commentRepository.findAllByParentId(parentId, pageable);

        return PageResponse.<CommentResponse>builder()
                .currentPage(page)
                .pageSize(pageData.getSize())
                .totalElements(pageData.getTotalElements())
                .data(pageData.getContent().stream().map(commentMapper::toCommentResponse).toList())
                .build();
    }

    public long getCountRepliesInComment(String parentId) {
        return commentRepository.countByParentId(parentId);
    }

    public long getCountCommentsInPost(String postId){
        return commentRepository.countByPostId(postId);
    }



    public CommentResponse getCommentById(String commentId){
        Comment comment = commentRepository.findById(commentId).orElseThrow(
                () -> new AppException(ErrorCode.COMMENT_NOT_FOUND)
        );

        return commentMapper.toCommentResponse(comment);
    }


    private String getProfileIdFromAuthentication(Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        String USER_ID = "userId";
        String userId = jwt.getClaimAsString(USER_ID);

        return userProfileClient.getActiveProfile(userId).getResult();
    }
}
