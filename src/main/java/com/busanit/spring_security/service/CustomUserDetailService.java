package com.busanit.spring_security.service;

import com.busanit.spring_security.model.User;
import com.busanit.spring_security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

// 스프링 시큐리티에서 사용자 정보를 로드하기 위한 클래스 (Security 의존성이 가지고 있는 인터페이스 상속)
@Service
public class CustomUserDetailService implements UserDetailsService {

    @Autowired  // 레포지토리 의존성 주입
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // username으로 User 객체 DB 조회 -> User 객체
        User user = userRepository.findByUsername(username);

        // 사용자가 없는 경우 예외발생
        if(user == null) {
            throw new UsernameNotFoundException("회원을 찾을 수 없습니다. ");
        }

        // UserDetails 객체(스프링 시큐리티가 관리)로 변환
        UserDetails userDetail = org.springframework.security.core.userdetails.User.builder()        // 우리가 만든 Entity 객체가 아님
                .username(user.getUsername())
                .password(user.getPassword())
                .roles("USER")      // 일반 사용자 역할
                .build();
        return userDetail;
    }





}
