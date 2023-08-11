package jacob.springbootjwttutorial.service;

import jacob.springbootjwttutorial.dto.UserDto;
import jacob.springbootjwttutorial.entity.Authority;
import jacob.springbootjwttutorial.entity.User;
import jacob.springbootjwttutorial.repository.UserRepository;
import jacob.springbootjwttutorial.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    // 회원 가입 수행하는 메소드
    public User signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            // userDto를 통해 해당 username이 DB에 저장되어 있는지 조회
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        // 권한정보를 만들고 이를 통해 user정보 만들기
        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        // 권한 정보와 유저 정보 repository에 저장
        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    // username으로 유저정보와 권한정보 가져옴
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    @Transactional(readOnly = true)
    // 현재 securityContext에 저장된 username 정보만 가져옴
    public Optional<User> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}
