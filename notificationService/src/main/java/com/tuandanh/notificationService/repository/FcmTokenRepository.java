package com.tuandanh.notificationService.repository;

import com.tuandanh.notificationService.entity.FcmToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface FcmTokenRepository extends MongoRepository<FcmToken, String> {
    Optional<FcmToken> findByToken(String token);
    List<FcmToken> findByUserId(String userId);
    void deleteByToken(String token);
}
