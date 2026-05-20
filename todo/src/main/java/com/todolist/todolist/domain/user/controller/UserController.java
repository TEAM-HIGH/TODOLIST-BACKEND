package com.todolist.todolist.domain.user.controller;

import com.todolist.todolist.domain.user.dto.request.UserRequest;
import com.todolist.todolist.domain.user.dto.response.UserResponse;
import com.todolist.todolist.domain.user.service.UserService;
import com.todolist.todolist.global.redis.RedisService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
public class UserController {

    private final UserService userService;

    @PostMapping("/login")
    public ResponseEntity<UserResponse> login(@RequestBody UserRequest userRequestDto) {
        UserResponse userResponse = userService.login(userRequestDto);
        return ResponseEntity.ok(userResponse);
    }

    @PostMapping("/signup")
    public void signup(@RequestBody UserRequest userRequestDto) {
        userService.signup(userRequestDto);
    }

    @PostMapping("/reissue")
    public ResponseEntity<String> reissueToken(@RequestHeader("Authorization") String accessToken, @CookieValue("refreshToken") String refreshToken) {
        String newAccessToken = userService.reissue(accessToken, refreshToken);
        return ResponseEntity.status(HttpStatus.OK).body(newAccessToken);
    }

    @PostMapping("/logout")
    public void logout(@RequestHeader("Authorization") String accessToken, @CookieValue("refreshToken") String refreshToken) {
        userService.logout(accessToken, refreshToken);
    }
}
