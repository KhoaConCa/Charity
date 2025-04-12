package com.tuandanh.PostService.repository;

import com.tuandanh.PostService.entity.Post;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface PostRepository extends MongoRepository<Post, String> {
    List<Post> findByProfileId(String profileId);
}
