package com.tuandanh.notificationService.service;

import com.tuandanh.notificationService.dto.request.FcmTokenRequest;
import com.tuandanh.notificationService.entity.FcmToken;
import com.tuandanh.notificationService.repository.FcmTokenRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class FcmService {
    FcmTokenRepository fcmTokenRepository;

    public void saveOrUpdateToken(FcmTokenRequest fcmTokenRequest) {
        String newToken = fcmTokenRequest.getToken();
        String userId = fcmTokenRequest.getUserId();
        Optional<FcmToken> existingToken = fcmTokenRepository.findByToken(newToken);

        if (existingToken.isPresent()) {
            // Cập nhật thời gian cập nhật
            FcmToken token = existingToken.get();
            token.setUpdatedAt(LocalDateTime.now());
            fcmTokenRepository.save(token);
        } else {
            // Thêm token mới
            FcmToken newEntry = FcmToken.builder()
                    .userId(userId)
                    .token(newToken)
                    .build();
            fcmTokenRepository.save(newEntry);
        }
    }

    public List<FcmToken> getTokensByUserId(String userId) {
        return fcmTokenRepository.findByUserId(userId);
    }

    public void deleteToken(String token) {
        fcmTokenRepository.deleteByToken(token);
    }
}
