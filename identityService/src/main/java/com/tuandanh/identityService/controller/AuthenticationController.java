package com.tuandanh.identityService.controller;

import com.nimbusds.jose.JOSEException;
import com.tuandanh.identityService.dto.ApiResponse;
import com.tuandanh.identityService.dto.request.*;
import com.tuandanh.identityService.dto.response.*;
import com.tuandanh.identityService.service.AuthenticationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Tag(name = "Authentication Controller", description = "Xác thực, ủy quyền và các chức năng liên quan đến bảo mật")
public class AuthenticationController {
    AuthenticationService authenticationService;

    @Operation(summary = "Bật xác thực 2 lớp (2FA)", description = "API bật 2FA cho tài khoản hiện tại")
    @PostMapping("enable-2fa")
    public ApiResponse<TwoFAResponse> enableTwoFA(){
        TwoFAResponse response = authenticationService.enable2FA();

        return ApiResponse.<TwoFAResponse>builder()
                .result(response)
                .build();
    }

    @Operation(summary = "Tắt xác thực 2 lớp (2FA)", description = "API tắt 2FA với mã OTP xác minh")
    @PostMapping("disable-2fa")
    public ApiResponse<TwoFAResponse> disableTwoFA(@RequestBody VerifyOtpRequest verifyOtpRequest){
        TwoFAResponse response = authenticationService.disable2FA(verifyOtpRequest);

        return ApiResponse.<TwoFAResponse>builder()
                .result(response)
                .build();
    }

    @Operation(summary = "Gửi OTP đăng nhập", description = "API gửi mã OTP để đăng nhập")
    @PostMapping("/send-otp-login")
    public ApiResponse<SendOtpResponse> sendOtpLogin() {
        SendOtpResponse sendOtpResponse = authenticationService.sendOtp(null);

        return ApiResponse.<SendOtpResponse>builder()
                .result(sendOtpResponse)
                .build();
    }

    @Operation(summary = "Xác minh OTP", description = "API kiểm tra mã OTP để xác thực đăng nhập")
    @PostMapping("/verify-otp")
    public ApiResponse<AuthenticationResponse> verifyOtp(@RequestBody VerifyOtpRequest verifyOtpRequest) {
        AuthenticationResponse authenticationResponseOtpResponse = authenticationService
                .verifyOtp(verifyOtpRequest);

        return ApiResponse.<AuthenticationResponse>builder()
                .result(authenticationResponseOtpResponse)
                .build();
    }

    @Operation(summary = "Gửi email xác thực", description = "API gửi email xác nhận để xác thực tài khoản")
    @PostMapping("/send-verify-email")
    public ApiResponse<VerifyEmailResponse> sendVerifyEmail(@RequestBody SendEmailRequest request) {
        VerifyEmailResponse verifyEmailResponse = authenticationService.sendVerifyEmail(request);

        return ApiResponse.<VerifyEmailResponse>builder()
                .result(verifyEmailResponse)
                .build();
    }

    @Operation(summary = "Gửi email xác thực khi đăng nhập", description = "API gửi email xác nhận khi đăng nhập")
    @PostMapping("/send-verify-email-login")
    public ApiResponse<VerifyEmailResponse> sendVerifyEmailLogIn() {
        VerifyEmailResponse verifyEmailResponse = authenticationService.sendVerifyEmailLogIn();

        return ApiResponse.<VerifyEmailResponse>builder()
                .result(verifyEmailResponse)
                .build();
    }

    @Operation(summary = "Xác nhận email", description = "API xác nhận email với mã xác nhận")
    @PostMapping("/confirm-verify-email")
    public ApiResponse<VerifyEmailConfirmResponse> confirmVerifyEmail(@RequestBody VerifyEmailConfirmRequest
                                                                                  request) {
        VerifyEmailConfirmResponse verifyEmailConfirmResponse = authenticationService
                .confirmVerifyEmail(request);

        return ApiResponse.<VerifyEmailConfirmResponse>builder()
                .result(verifyEmailConfirmResponse)
                .build();
    }

    @Operation(summary = "Quên mật khẩu", description = "API gửi email đặt lại mật khẩu")
    @PostMapping("/forgot-password")
    public ApiResponse<ForgotPasswordResponse> forgotPassword(@RequestBody ForgotPasswordRequest
                                                                          forgotPasswordRequest) {
        ForgotPasswordResponse forgotPasswordResponse = authenticationService.processForgotPassword(
                forgotPasswordRequest);

        return ApiResponse.<ForgotPasswordResponse>builder()
                .result(forgotPasswordResponse)
                .build();
    }

    @Operation(summary = "Đặt lại mật khẩu", description = "API dùng để đặt lại mật khẩu với mã xác nhận")
    @PostMapping("/reset-password")
    public ApiResponse<ResetPasswordResponse> resetPassword(@RequestBody ResetPasswordRequest
                                                                        resetPasswordRequest) {
        ResetPasswordResponse resetPasswordResponse = authenticationService
                .resetPassword(resetPasswordRequest);

        return ApiResponse.<ResetPasswordResponse>builder()
                .result(resetPasswordResponse)
                .build();
    }

    @Operation(summary = "Đăng nhập", description = "API xác thực và cấp token cho tài khoản")
    @PostMapping("/token")
    ApiResponse<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
        var result = authenticationService.authenticate(request);
        return ApiResponse.<AuthenticationResponse>builder()
                .result(result)
                .build();
    }

    @Operation(summary = "Kiểm tra token (Introspect)", description = "API kiểm tra tính hợp lệ của token")
    @PostMapping("/introspect")
    ApiResponse<IntrospectResponse> authenticate(@RequestBody IntrospectRequest request)
            throws ParseException, JOSEException {
        var result = authenticationService.introspect(request);
        return ApiResponse.<IntrospectResponse>builder()
                .result(result)
                .build();
    }

    @Operation(summary = "Đăng xuất", description = "API đăng xuất và thu hồi token")
    @PostMapping("/logout")
    ApiResponse<Void> logout(@RequestBody LogoutRequest request) throws ParseException, JOSEException {
        authenticationService.logout(request);
        return ApiResponse.<Void>builder().build();
    }

    @Operation(summary = "Làm mới token", description = "API cấp lại token mới khi token cũ hết hạn")
    @PostMapping("/refresh")
    ApiResponse<AuthenticationResponse> authenticate(@RequestBody RefreshRequest request)
            throws ParseException, JOSEException {
        var result = authenticationService.refreshToken(request);
        return ApiResponse.<AuthenticationResponse>builder().result(result).build();
    }

    @Operation(summary = "Xử lý lỗi khi xác thực OAuth2 thất bại", description = "API xử lý thông báo khi đăng nhập OAuth2 thất bại")
    @GetMapping("/failure-in-oauth2")
    public ApiResponse<String> handleFailure() {
        return ApiResponse.<String>builder()
                .result(authenticationService.noticeWhenOauth2Failure())
                .build();
    }
}
