package com.tuandanh.PostService.repository;

import com.tuandanh.PostService.entity.Reaction;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface ReactionRepository extends MongoRepository<Reaction, String> {
    Reaction findByPostIdAndProfileId(String postId, String profileId);
}
