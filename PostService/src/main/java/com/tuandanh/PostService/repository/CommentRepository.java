package com.tuandanh.PostService.repository;

import com.tuandanh.PostService.entity.Comment;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface CommentRepository extends MongoRepository<Comment, String> {
}
