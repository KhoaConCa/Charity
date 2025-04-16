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
    Reaction findByPostIdAndProfileIdAndReactionType(String postId, String profileId, ReactionType reactionType);
    List<Reaction> findAllByPostId(String postId);
    void deleteAllByPostId(String postId);
    void deleteAllByProfileId(String profileId);
    long countByPostId(String postId);
    Page<Reaction> findAllByPostId(String postId, Pageable pageable);
}
