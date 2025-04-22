package com.tuandanh.notificationService.exception;

import org.springframework.http.HttpStatus;

public enum ErrorCode {
    UNCATEGORIZED_EXCEPTION(9999, "Uncategorized error", HttpStatus.INTERNAL_SERVER_ERROR),

    INVALID_KEY(1001, "Invalid key provided", HttpStatus.BAD_REQUEST),
    UNAUTHENTICATED(1004, "User is unauthenticated", HttpStatus.UNAUTHORIZED),
    UNAUTHORIZED(1015, "Unauthorized", HttpStatus.FORBIDDEN),
    CANNOT_SEND_EMAIL(1016, "Can't send email", HttpStatus.INTERNAL_SERVER_ERROR),
    PROFILE_EXISTED(1017, "Profile already exists", HttpStatus.CONFLICT),
    NOTIFICATION_NOT_FOUND(1018, "Notification not found", HttpStatus.NOT_FOUND),
    ;
    private final int code;
    private final String message;
    private final HttpStatus httpStatus;

    ErrorCode(int code, String message, HttpStatus httpStatus) {
        this.code = code;
        this.message = message;
        this.httpStatus = httpStatus;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
