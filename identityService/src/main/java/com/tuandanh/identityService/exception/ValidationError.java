package com.tuandanh.identityService.exception;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@AllArgsConstructor
@Builder
public class ValidationError {
    private String field;
    private int code;
    private String message;
}
