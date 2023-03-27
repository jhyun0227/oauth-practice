package com.cos.security1.config.auth;

import com.cos.security1.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Security가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
 * 로그인 진행 완료가 되면 security session을 만들어준다. (Security ContextHolder)
 * Security ContextHolder에는 오브젝트, Authentication 타입 객체만이 들어갈 수 있다.
 * 그리고 Session을 위해 Authentication 객체 안에 User 정보가 있어야 한다.
 * User 오브젝트 타입 => UserDetails 타입 객체
 *
 * Security Session(Security ContextHolder) 안에는 Authentication 객체가 들어가야하고,
 * Authentication 객체안에 들어갈 유저의 정보는 UserDetails(PrincipalDetails) 객체이어야만 한다.
 */
public class PrincipalDetails implements UserDetails {

    //컴포지션
    private User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    /**
     * 해당 유저의 권한을 리턴하는 메서드
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> collect = new ArrayList<>();

        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });

        return collect;
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
