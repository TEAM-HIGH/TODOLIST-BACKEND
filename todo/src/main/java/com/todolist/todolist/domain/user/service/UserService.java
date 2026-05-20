package com.todolist.todolist.domain.user.service;

import com.todolist.todolist.domain.user.UserRole;
import com.todolist.todolist.domain.user.dto.request.UserRequest;
import com.todolist.todolist.domain.user.dto.response.UserResponse;
import com.todolist.todolist.domain.user.entity.UserEntity;
import com.todolist.todolist.domain.user.repository.UserRepository;
import com.todolist.todolist.global.jwt.JwtTokenProvider;
import com.todolist.todolist.global.redis.RedisService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisService redisService;
    private final StringRedisTemplate redisTemplate;

    @Transactional
    public UserResponse login(UserRequest userRequestDto) {
//        //이렇게 작성하면 사용자 이름만 존재 여부를 판단함.
//        if(!userRepository.existsByUsername(userRequestDto.getUsername())) {
//            throw new IllegalArgumentException("Username not found");
//        }
          //이렇게 하면 사용자 이름 여부와 userentity 객체 가져올 수 있음
          UserEntity userEntity = userRepository.findByUsername(userRequestDto.getUsername())
                  .orElseThrow(()-> new IllegalArgumentException("사용자 존재하지 않음"));

          if(!passwordEncoder.matches(userRequestDto.getPassword(), userEntity.getPassword())){
              throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
          }

          String accessToken = jwtTokenProvider.createAccessToken(userEntity.getUsername(), userEntity.getRole());
          String refreshToken = jwtTokenProvider.createRefreshToken(userEntity.getUsername());

          redisService.setValues(
                  userEntity.getUsername(),
                  refreshToken,
                  Duration.ofDays(14)
          );

        log.info("🚩 Redis 저장 시도 완료! Key: {}, Value: {}", userEntity.getUsername(), refreshToken);
          return new UserResponse(accessToken, refreshToken);
    }

    @Transactional
    public void signup(UserRequest userRequestDto) {

        String username = userRequestDto.getUsername();
        String password = passwordEncoder.encode(userRequestDto.getPassword());

        if(userRepository.existsByUsername(userRequestDto.getUsername())){
            throw new IllegalArgumentException("해당 이름으로 가입된 사용자가 있습니다.");
        }

        UserEntity userEntity = UserEntity.builder()
                .username(username)
                .password(password)
                .Role(UserRole.USER)
                .build();

        userRepository.save(userEntity);
    }

    @Transactional
    public void logout(String accessToken, String refreshToken) {
        // 1. Access Token 유효성 검증
        // 일단 받고 검사해야함
        if (!jwtTokenProvider.validateToken(accessToken)) {
            log.warn("이미 만료되었거나 잘못된 Access Token으로 로그아웃을 시도했습니다.");
        }

        // 2. Refresh Token 유효성 검증
        // 이유는
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new IllegalArgumentException("유효하지 않은 Refresh Token입니다.");
        }

        // 3. Refresh Token에서 유저 정보(Username) 추출
        String username = jwtTokenProvider.getUsername(refreshToken);

        if (redisTemplate.opsForValue().get(username) != null) {
            redisTemplate.delete(username);
            log.info("유저 [{}]의 Refresh Token을 Redis에서 삭제했습니다.", username);
        } else {
            log.warn("유저 [{}]의 Refresh Token이 이미 Redis에 존재하지 않습니다.", username);
        }

        // 5. (선택) Access Token 블랙리스트 추가 로직을 여기에 작성할 수 있습니다.
    }

    public String reissue(String accessToken, String refreshToken) {
        // 1. Refresh Token 자체의 유효성 검사
//        if (!jwtTokenProvider.validateToken(refreshToken)) {
//            throw new RuntimeException("Refresh Token이 만료되었거나 유효하지 않습니다. 다시 로그인하세요.");
//        }

        // 2. Access Token에서 정보 추출 (만료되어도 Claims를 꺼낼 수 있는 메서드 필요)
        // Bearer 접두사가 붙어있다면 제거하는 로직 추가
        String pureToken = accessToken.replace("Bearer ", "");
        Claims claims = jwtTokenProvider.getClaimsFromExpiredToken(pureToken);

        String username = claims.getSubject();
        log.info("요청된 유저: {}", username);
        log.info("쿠키로 온 토큰: {}", refreshToken);
        log.info("DB에 있는 토큰: {}", redisTemplate.opsForValue().get(username));
        log.info("Redis에서 찾으려는 키: [{}]", username); // 이게 "RT:"가 붙었는지 안 붙었는지 확인!
        // 토큰 생성 시 넣었던 권한 키값("auth")으로 꺼내기
        String roleString = claims.get("auth", String.class);
        UserRole role = UserRole.valueOf(roleString.replace("ROLE_", ""));
        // 3. Redis에 저장된 해당 유저의 Refresh Token 가져오기
        String savedRefreshToken = redisTemplate.opsForValue().get(username);

        // 4. Redis 검증: 토큰이 없거나 클라이언트가 보낸 것과 다르면 거절
        if (savedRefreshToken == null || !savedRefreshToken.equals(refreshToken)) {
            throw new RuntimeException("Refresh Token 정보가 일치하지 않거나 서버에 존재하지 않습니다.");
        }

        // 5. 새로운 Access Token 생성 및 반환
        return jwtTokenProvider.createAccessToken(username, role);
    }
}
