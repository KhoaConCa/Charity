package com.tuandanh.PostService.repository;

import com.tuandanh.PostService.entity.Comment;
import com.tuandanh.PostService.entity.Post;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface CommentRepository extends MongoRepository<Comment, String> {
    Page<Comment> findAllByPostId(String postId, Pageable pageable);
    List<Comment> findAllByParentId(String parenId);
    List<Comment> findByPostId(String postId);
    Page<Comment> findAllByParentId(String parentId, Pageable pageable);
    Page<Comment> findAllByProfileId(String profileId, Pageable pageable);
    long countByParentId(String parenId);
    long countByPostId(String postId);
    void deleteByPostId(String postId);
    void deleteByProfileId(String profileId);
}
