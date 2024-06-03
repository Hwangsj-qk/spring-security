package com.busanit.spring_security.controller;

import com.busanit.spring_security.model.User;
import com.busanit.spring_security.service.CustomUserDetailService;
import com.busanit.spring_security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @Autowired
    UserDetailsService userDetailsService;

    @Autowired
    UserService userService;        // 일반 유저 서비스 DI

    @Autowired
    CustomUserDetailService userDetailService;      // 스프링 시큐리티 유저 서비스 DI

    @Autowired
    private AuthenticationManager authenticationManager;        // 인증 관리자 DI

    @PostMapping("/auth")
    public String auth(@RequestBody User user) throws Exception {
        // 스프링 시큐리티 인증관리자로 사용자로부터 받은 정보로 인증 토큰을 생성하여 인증
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    user.getUsername(),
                    user.getPassword()
            ));
        } catch (BadCredentialsException e) {
            // 인증 실패되는 경우
            throw new Exception("인증을 실패하였습니다.");
        }
        // 인증된 사용자 정보를 가져옴
        userDetailService.loadUserByUsername(user.getUsername());
        String msg = String.format("%s님 성공적으로 인증되었습니다", user.getUsername());
        return msg;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user) {
        userService.saveUser(user);
        return ResponseEntity.ok("회원 가입 완료");
    }
}
