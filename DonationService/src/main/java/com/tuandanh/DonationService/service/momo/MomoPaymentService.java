package com.tuandanh.DonationService.service.momo;

import com.nimbusds.jose.shaded.gson.Gson;
import com.tuandanh.DonationService.dto.request.MomoPaymentRequest;
import com.tuandanh.DonationService.dto.response.PostResponse;
import com.tuandanh.DonationService.dto.response.ProfileResponse;
import com.tuandanh.DonationService.entity.Donation;
import com.tuandanh.DonationService.entity.MoMoPayment;
import com.tuandanh.DonationService.entity.PaymentLog;
import com.tuandanh.DonationService.enums.*;
import com.tuandanh.DonationService.exception.AppException;
import com.tuandanh.DonationService.exception.ErrorCode;
import com.tuandanh.DonationService.repository.DonationRepository;
import com.tuandanh.DonationService.repository.MomoPaymentRepository;
import com.tuandanh.DonationService.repository.PaymentLogRepository;
import com.tuandanh.DonationService.repository.httpClient.PostClient;
import com.tuandanh.DonationService.repository.httpClient.UserProfileClient;
import com.tuandanh.event.dto.NotificationEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class MomoPaymentService {
    private final PaymentLogRepository paymentLogRepository;
    private final DonationRepository donationRepository;
    private final MomoPaymentRepository momoPaymentRepository;
    private final UserProfileClient userProfileClient;
    private final PostClient postClient;
    private final KafkaTemplate<String, NotificationEvent> kafkaTemplate;

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${momo.partner-code}")
    private String partnerCode;

    @Value("${momo.access-key}")
    private String accessKey;

    @Value("${momo.secret-key}")
    private String secretKey;

    @Value("${momo.redirect-url}")
    private String redirectUrl;

    @Value("${momo.ipn-url}")
    private String ipnUrl;

    @Value("${momo.endpoint}")
    private String momoEndpoint;

    public String handleIPN(Map<String, Object> payload){

        // 2. Parse dữ liệu
        String orderId = (String) payload.get("orderId"); // bạn dùng orderId làm donation.id rồi
        MoMoPayment paymentRequest = momoPaymentRepository.findByOrderId(orderId)
                .orElseThrow(() -> new AppException(ErrorCode.ORDER_ID_NOT_FOUND));

        int resultCode = Integer.parseInt(payload.get("resultCode").toString());

        // Lấy donationId từ paymentRequest và tìm donation tương ứng
        Optional<Donation> optional = donationRepository.findById(paymentRequest.getDonationId());
        if (optional.isEmpty()) throw new AppException(ErrorCode.DONATION_NOT_FOUND);
        Donation donation = optional.get();

        // 1. Lưu log
        PaymentLog log = new PaymentLog();
        log.setGatewayName("MOMO");
        log.setPayload(new Gson().toJson(payload));
        log.setStatus(PaymentLogStatus.RECEIVED);
        log.setCreatedAt(LocalDateTime.now());
        log.setDonationId(donation.getId());
        paymentLogRepository.save(log);


        if (resultCode == 0) {
            ProfileResponse profileResponse = userProfileClient.getProfile(donation.getDonorId()).getResult();
            PostResponse postResponse = postClient.getPostByPostId(donation.getPostId()).getResult();
            String senderName = profileResponse.getUsername();
            Map<String, Object> params = new HashMap<>();
            params.put("senderId", donation.getDonorId());
            params.put("userId", postResponse.getProfileId());
            params.put("notificationType", NotificationType.DONATION);
            // Gửi thông báo qua Kafka cho receiver (User B) về lời mời kết bạn từ User A
            NotificationEvent notificationEvent = NotificationEvent.builder()
                    .chanel(CHANEL.PUSH_NOTIFICATION)
                    .recipient(postResponse.getProfileId())  // Người nhận thông báo là receiverId
                    .param(params)
                    .subject("Thông báo về donation")
                    .body("User " + senderName + " đã quyên góp cho bạn " + donation.getAmount() + "VND.")
                    .build();

            kafkaTemplate.send(KafkaTopic.NEW_DONATION.getTopic(),notificationEvent);  // Gửi message qua Kafka
            donation.setStatus(DonationStatus.SUCCESS);
            donation.setPaidAt(LocalDateTime.now());
            donation.setPaymentRefId((Long) payload.get("transId"));
        } else {
            donation.setStatus(DonationStatus.FAILED);
        }

        donationRepository.save(donation);

        return "Payment Log successfully";
    }

    public String createPayment(Donation donation) {
        String orderId = donation.getId();
        String requestId = UUID.randomUUID().toString();

        // Lưu vào bảng mapping
        MoMoPayment momoPaymentRequest = new MoMoPayment();
        momoPaymentRequest.setOrderId(orderId);
        momoPaymentRequest.setRequestId(requestId);
        momoPaymentRequest.setDonationId(donation.getId());
        momoPaymentRequest.setCreatedAt(LocalDateTime.now());

        momoPaymentRepository.save(momoPaymentRequest);

        String rawSignature = "accessKey=" + accessKey +
                "&amount=" + donation.getAmount().toString() +
                "&extraData=" +
                "&ipnUrl=" + ipnUrl +
                "&orderId=" + orderId +
                "&orderInfo=" + "Thanh toan donation" +
                "&partnerCode=" + partnerCode +
                "&redirectUrl=" + redirectUrl +
                "&requestId=" + requestId +
                "&requestType=captureWallet";

        String signature = hmacSHA256(rawSignature, secretKey);

        Map<String, String> body = new HashMap<>();
        body.put("partnerCode", partnerCode);
        body.put("accessKey", accessKey);
        body.put("requestId", requestId);
        body.put("amount", donation.getAmount().toString());
        body.put("orderId", orderId);
        body.put("orderInfo", "Thanh toan donation");
        body.put("redirectUrl", redirectUrl);
        body.put("ipnUrl", ipnUrl);
        body.put("extraData", "");
        body.put("requestType", "captureWallet");
        body.put("lang", "vi");
        body.put("signature", signature);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(momoEndpoint, request, Map.class);
        return response.getBody().get("payUrl").toString();
    }

    private String hmacSHA256(String data, String key) {
        try {
            Mac hmacSha256 = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            hmacSha256.init(secretKeySpec);
            byte[] hash = hmacSha256.doFinal(data.getBytes(StandardCharsets.UTF_8));

            // CHỖ NÀY: convert to hex (NOT Base64)
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString(); // hex lowercase
        } catch (Exception e) {
            throw new RuntimeException("Lỗi tạo chữ ký", e);
        }
    }

}

