package com.tuandanh.DonationService.service;

import com.tuandanh.DonationService.dto.PageResponse;
import com.tuandanh.DonationService.dto.PostDonationTotal;
import com.tuandanh.DonationService.dto.request.DonationCreationRequest;
import com.tuandanh.DonationService.dto.response.DonationResponse;
import com.tuandanh.DonationService.entity.Donation;
import com.tuandanh.DonationService.entity.PaymentLog;
import com.tuandanh.DonationService.enums.DonationStatus;
import com.tuandanh.DonationService.exception.AppException;
import com.tuandanh.DonationService.exception.ErrorCode;
import com.tuandanh.DonationService.mapper.DonationMapper;
import com.tuandanh.DonationService.repository.DonationRepository;
import com.tuandanh.DonationService.repository.PaymentLogRepository;
import com.tuandanh.DonationService.service.momo.MomoPaymentService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class DonationService {
    DonationRepository donationRepository;
    DonationMapper donationMapper;
    MomoPaymentService momoPaymentService;
    PaymentLogRepository paymentLogRepository;

    public BigDecimal getTotalByPostId(String postId) {
        return donationRepository.getTotalByPostId(postId);
    }

    public List<PostDonationTotal> getAllPostDonationTotals() {
        return donationRepository.getTotalDonationByPost();
    }

    public DonationResponse createDonation(DonationCreationRequest donationCreationRequest){
        Donation donation = donationMapper.toDonation(donationCreationRequest);
        donation.setCreatedAt(LocalDateTime.now());
        donation.setStatus(DonationStatus.PENDING);

        // 1. Lưu vào DB trước
        Donation savedDonation = donationRepository.save(donation);
        PaymentLog paymentLog = PaymentLog.builder()
                .donationId(savedDonation.getId())
                .build();

        paymentLogRepository.save(paymentLog);



        // 2. Gọi MOMO để tạo đơn thanh toán
        String payUrl = momoPaymentService.createPayment(savedDonation);

        // 3. Tạo response và đính kèm payUrl
        DonationResponse response = donationMapper.toDonationResponse(savedDonation);
        response.setPayUrl(payUrl); // 👈 nhớ set cái này

        return response;
    }

    public DonationResponse getDonationById(String donationId){
        Donation donation = donationRepository.findById(donationId).orElseThrow(
                () -> new AppException(ErrorCode.DONATION_NOT_FOUND)
        );

        return donationMapper.toDonationResponse(donation);
    }

    public PageResponse<DonationResponse> getAllDonationOfUser(String donorId, int page, int size){
        Sort sort = Sort.by("createdAt").descending();
        Pageable pageable = PageRequest.of(page - 1, size, sort);
        var pageData = donationRepository.findAllByDonorId(donorId, pageable);

        return PageResponse.<DonationResponse>builder()
                .currentPage(page)
                .pageSize(pageData.getSize())
                .totalElements(pageData.getTotalElements())
                .data(pageData.getContent().stream().map(donationMapper::toDonationResponse).toList())
                .build();
    }

    public PageResponse<DonationResponse> getAllDonationOfPost(String postId, int page, int size){
        Sort sort = Sort.by("createdAt").descending();
        Pageable pageable = PageRequest.of(page - 1, size, sort);
        var pageData = donationRepository.findAllByPostId(postId, pageable);

        return PageResponse.<DonationResponse>builder()
                .currentPage(page)
                .pageSize(pageData.getSize())
                .totalElements(pageData.getTotalElements())
                .data(pageData.getContent().stream().map(donationMapper::toDonationResponse).toList())
                .build();
    }
}
