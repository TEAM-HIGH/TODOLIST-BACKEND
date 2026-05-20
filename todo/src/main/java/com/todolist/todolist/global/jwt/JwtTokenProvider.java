package com.todolist.todolist.global.jwt;
import com.todolist.todolist.domain.user.UserRole;
import com.todolist.todolist.global.security.CustomUserDetailsService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;
@Slf4j
@Component
public class JwtTokenProvider {

    private final Key key;
    private final long accessTokenTime = 30 * 60 * 1000L;
    private final long refreshTokenTime = 14 * 24 * 60 * 60 * 1000L;

    // 추가: 우리가 만든 서비스를 주입받습니다.
    private final CustomUserDetailsService customUserDetailsService;

    // 생성자 수정: @Value와 서비스를 함께 주입받도록 설정
    public JwtTokenProvider(@Value("${jwt.secret.key}") String secretKey,
                            CustomUserDetailsService customUserDetailsService) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.customUserDetailsService = customUserDetailsService;
    }

    // 2. Access Token 생성 (동일)
    public String createAccessToken(String username, UserRole role) {
        Date now = new Date();
        return Jwts.builder()
                .setSubject(username)
                .claim("auth", "ROLE_" + role)
                .setExpiration(new Date(now.getTime() + accessTokenTime))
                .setIssuedAt(now)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // 3. Refresh Token 생성 (동일)
    public String createRefreshToken(String username) {
        Date now = new Date();
        return Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(now.getTime() + refreshTokenTime))
                .setIssuedAt(now)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // ⭐ 4. 토큰에서 Authentication(인증 객체) 생성 (수정됨)
    public Authentication getAuthentication(String token) {
        // 토큰에서 유저 식별값(Subject)을 꺼냅니다.
        String username = getUserInfoFromToken(token).getSubject();

        // [변경 포인트] DB에서 유저 정보를 직접 조회하여 CustomUserDetails를 가져옵니다.
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

        // [변경 포인트] 두 번째 인자인 비밀번호는 시큐리티 내부에서 필요 없으므로 빈 문자열로 둡니다.
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    // 5. 토큰 유효성 검증 (동일)
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.error("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.error("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.error("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.error("JWT 토큰이 비어있습니다.");
        }
        return false;
    }

    public Claims getClaimsFromExpiredToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key) // Provider에 정의된 key
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            // ★ 만료되었을 때 던져지는 예외 안에는 만료 전의 Claims 정보가 그대로 들어있습니다.
            return e.getClaims();
        } catch (Exception e) {
            throw new RuntimeException("유효하지 않은 토큰입니다.");
        }
    }
    // 6. 토큰에서 Claims(사용자 정보) 추출 (동일)
    public Claims getUserInfoFromToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    //
    public String getUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key) // 아까 설정한 서명 키
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject(); // 보통 subject(sub) 필드에 유저네임을 넣습니다.
    }

    // ⭐ 7. 추가: 헤더에서 토큰을 추출하는 도구 (필터에서 필수!)
    public String resolveAccessToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}