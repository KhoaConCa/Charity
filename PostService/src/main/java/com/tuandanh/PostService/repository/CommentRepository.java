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
    Page<Comment> findAllByParentId(String parenId, Pageable pageable);
    long countByParentId(String parenId);
    long countByPostId(String postId);
}
