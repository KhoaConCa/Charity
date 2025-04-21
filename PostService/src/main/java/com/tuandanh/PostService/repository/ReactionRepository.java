package com.tuandanh.PostService.repository;

import com.tuandanh.PostService.entity.Post;
import com.tuandanh.PostService.entity.Reaction;
import com.tuandanh.PostService.enums.ReactionType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface ReactionRepository extends MongoRepository<Reaction, String> {
    Reaction findByPostIdAndProfileId(String postId, String profileId);
    Reaction findByCommentIdAndProfileId(String commentId, String profileId);
    Reaction findByPostIdAndProfileIdAndReactionType(String postId, String profileId, ReactionType reactionType);
    List<Reaction> findAllByPostId(String postId);
    List<Reaction> findAllByCommentId(String commentId);
    void deleteAllByPostId(String postId);
    void deleteAllByProfileId(String profileId);
    void deleteAllByCommentId(String commentId);
    void deleteByPostId(String postId);
    long countByPostId(String postId);
    long countByCommentId(String commentId);
    Page<Reaction> findAllByPostId(String postId, Pageable pageable);
    Page<Reaction> findAllByCommentId(String commentId, Pageable pageable);
}
