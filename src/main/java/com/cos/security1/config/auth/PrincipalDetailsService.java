package com.cos.security1.config.auth;

import com.cos.security1.entity.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * SecurityConfig에서 loginProcessingUrl("/login");
 * /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadByUsername 함수 호
 */

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * username 파라미터를 잘 맞춰주어야 한다. 아니면 SecurityConfig에 .usernameParameter()함수를 추가해야한다.
     * Security ContextHolder(Authentication(UserDetails)) => 이렇게 보관된다.
     *
     * 함수 종료 시 @AuthenticationPrincipal 어노테이션이 만들어진다.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("username = " + username);
        Optional<User> user = userRepository.findByUsername(username);
        if (user.isPresent()) {
            return new PrincipalDetails(user.get());
        }

        return null;
    }
}
