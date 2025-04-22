package com.tuandanh.notificationService.repository;

import com.tuandanh.notificationService.entity.FakeNotificationLog;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface FakeNotificationLogRepository extends MongoRepository<FakeNotificationLog, String> {
    List<FakeNotificationLog> findByUserId(String userId);
    List<FakeNotificationLog> findByUserIdAndIsReadFalseOrderByCreatedAtDesc(String userId);
}
