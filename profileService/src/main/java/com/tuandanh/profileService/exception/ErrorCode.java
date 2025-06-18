package com.tuandanh.profileService.exception;

import org.springframework.http.HttpStatus;

public enum ErrorCode {
    PROFILE_NOT_EXISTED(1003,"profile not existed", HttpStatus.NOT_FOUND),
    PROFILE_EXISTED(1002, "Profile Existed", HttpStatus.CONFLICT),
    UNCATEGORIZED_EXCEPTION(9999, "Uncategorized error", HttpStatus.INTERNAL_SERVER_ERROR),

    INVALID_KEY(1001, "Invalid key provided", HttpStatus.BAD_REQUEST),
    UNAUTHENTICATED(1004, "User is unauthenticated", HttpStatus.UNAUTHORIZED),
    UNAUTHORIZED(1015, "Unauthorized", HttpStatus.FORBIDDEN),
    USERNAME_INVALID(1006, "Username must be at least 3 characters and cannot be blank", HttpStatus.BAD_REQUEST),
    FIRSTNAME_INVALID(1007, "First name cannot exceed 30 characters and cannot be blank", HttpStatus.BAD_REQUEST),
    LASTNAME_INVALID(1008, "Last name cannot exceed 30 characters and cannot be blank", HttpStatus.BAD_REQUEST),
    URL_AVATAR_INVALID(1009, "Avatar invalid, please choose another avatar", HttpStatus.BAD_REQUEST),
    LOCATION_INVALID(1010, "Location invalid, please change the location", HttpStatus.BAD_REQUEST),
    FOLLOW_INVALID(1011, "Follow invalid, please choose another follow", HttpStatus.BAD_REQUEST),
    CANNOT_FOLLOW_OWN_PROFILE(1012, "Can't follow own profile", HttpStatus.BAD_REQUEST),
    NOT_FOLLOWING_YET(1013, "Not following yet", HttpStatus.BAD_REQUEST),
    ALREADY_FOLLOWING(1014, "Already Following", HttpStatus.CONFLICT),
    FRIEND_REQUEST_NOT_FOUND(1015, "Friend request not found", HttpStatus.NOT_FOUND),
    CANNOT_BLOCK_OWN_PROFILE(1016, "Can't block own profile", HttpStatus.BAD_REQUEST),
    ALREADY_BLOCKING(1017, "Already Blocking", HttpStatus.CONFLICT),
    NOT_BLOCKING_YET(1018, "Not blocking yet", HttpStatus.BAD_REQUEST),
    ALREADY_SENT_REQUEST_FRIEND(1019, "Already Sent request friend", HttpStatus.BAD_REQUEST),
    REQUEST_FRIEND_ALREADY_RECEIVED(1020, "Request friend is already received", HttpStatus.CONFLICT),
    ALREADY_FRIENDS(1021, "Already Friends", HttpStatus.CONFLICT),
    ALREADY_ACCEPTED_REQUEST_FRIEND(1022, "Already Accepted request friend", HttpStatus.CONFLICT),
    CANNOT_DECLINE_FRIEND_REQUEST(1023, "Can't decline friend request", HttpStatus.BAD_REQUEST),
    CANNOT_REMOVE_FRIEND_REQUEST(1024, "Can't remove friend request", HttpStatus.BAD_REQUEST),
    CANNOT_CANCEL_FRIEND_REQUEST(1025, "Can't cancel friend request", HttpStatus.BAD_REQUEST),
    DONT_HAVE_PERMISSION_TO_DECLINE(1026, "Don't have permission to decline", HttpStatus.BAD_REQUEST),
    ALREADY_REMOVED(1027, "Already Removed", HttpStatus.CONFLICT),
    ALREADY_DECLINED(1028, "Already Declined", HttpStatus.CONFLICT),
    DONT_HAVE_PERMISSION_TO_ACCEPT(1029, "Don't have permission to accept", HttpStatus.BAD_REQUEST),
    CANNOT_FOLLOW_DUE_TO_BLOCK(1030, "Can't follow due to block", HttpStatus.BAD_REQUEST),
    CANNOT_ADD_FRIEND_DUE_TO_BLOCK(1031, "Can't add friend due to block", HttpStatus.BAD_REQUEST),
    INVALID_TOKEN(1032, "Invalid token", HttpStatus.BAD_REQUEST),
    BIO_INVALID(1033, "Invalid Bio", HttpStatus.BAD_REQUEST),
    INVALID_URL_AWS3(1034, "Invalid aws3 url", HttpStatus.BAD_REQUEST)
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
