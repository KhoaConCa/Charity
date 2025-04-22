package com.tuandanh.DonationService.mapper;

import com.tuandanh.DonationService.dto.request.DonationCreationRequest;
import com.tuandanh.DonationService.dto.response.DonationResponse;
import com.tuandanh.DonationService.entity.Donation;
import com.tuandanh.DonationService.repository.DonationRepository;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface DonationMapper {
    DonationResponse toDonationResponse(Donation donation);
    Donation toDonation(DonationCreationRequest donationCreationRequest);
}
