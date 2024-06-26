package com.busanit.spring_security.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor @NoArgsConstructor
@Entity
@Table(name = "users")      // Entity 이름은 "User"이지만 테이블 이름은 "users"
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    // NOT NULL, UNIQUE 제약조건 (사용자이름: 필수, 중복불가)
    @Column(nullable = false, unique = true)
    private String username;
    // NOT NULL (비밀번호 : 필수)
    @Column(nullable = false)
    private String password;

}
