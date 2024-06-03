package com.busanit.spring_security.jwt;

import com.busanit.spring_security.service.CustomUserDetailService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
// 스프링 웹 필터 클래스를 상속받는 Jwt 요청 필터
@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    @Autowired      // DI
    private CustomUserDetailService userDetailService;

    @Autowired      // DI
    private JwtUtil jwtUtil;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // HTTP 요청 헤더에서 Authorization 정보를 가져옴
        String authorization = request.getHeader("Authorization");

        String jwt = null;
        String username = null;
        // 인증 헤더 정보가 존재하고 "Bearer "로 시작하면
        if(authorization != null && authorization.startsWith("Bearer ")) {      // ※ Bearer : 토큰 동반자 -> 토큰 앞에는 이 단어가 항상 붙음
            jwt = authorization.substring(7);   // Jwt 토큰 추출 (7글자 : Bearer )
            username = jwtUtil.extractUsername(jwt);     // 사용자이름 추출
        }

        // 토큰에서 사용자 이름은 존재하는데, SecurityContextHolder 에 인증되지 않은 경우
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // 사용자 정보를 불러옴
            UserDetails userDetails = this.userDetailService.loadUserByUsername(username);

            // 사용자 정보를 불러오니, 토큰이 유효한 경우
            if(jwtUtil.validateToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                        // 인가: 인증된 유저는 어떤 권한을 가지고 있는가? -> 인증(유저인가 아닌가 자체를 구분)과 구분
                );
                // 인증 요청 세부정보를 설정
                authToken.setDetails(
                        new WebAuthenticationDetailsSource()
                                .buildDetails(request)
                );
                // SecurityContext 에 인증 정보를 설정
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        // 다음 필터로 요청, 응답 정보 전달
        filterChain.doFilter(request, response);

    }
}
