package com.tuandanh.PostService.repository;

import com.tuandanh.PostService.entity.Post;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface PostRepository extends MongoRepository<Post, String> {
    List<Post> findByProfileId(String profileId);
    Page<Post> findAllByProfileId(String profileId, Pageable pageable);
    Page<Post> findAll(Pageable pageable);
}

