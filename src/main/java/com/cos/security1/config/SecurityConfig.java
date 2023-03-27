package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity //Security 활성화, Security 필터가 Spring FilterChain에 등록된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //secured 어노테이션 활성, preAuthorize/postAuthorize 어노테이션 활성
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()

                .authorizeRequests()
                .antMatchers("/user/**").authenticated() //인증만 되면 들어갈 수 있는 주소
                .antMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll()

                //권한이 없는 페이지에 요청이 들어왔을때 로그인 페이지로 이동시킨다.
                .and()
                .formLogin()
                .loginPage("/loginForm")
                // /login 주소가 호출이 되면 시큐리티출가 낚아채서 대신 로그인을 진행한다.
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/")

                //Social 로그인 설정
                .and()
                .oauth2Login()
                .loginPage("/loginForm"); //구글 로그인이 완료된 이후 후처리 필요

        return http.build();
    }

    /*
    기존: WebSecurityConfigurerAdapter를 상속하고 configure매소드를 오버라이딩하여 설정하는 방법
    => 현재: SecurityFilterChain을 리턴하는 메소드를 빈에 등록하는 방식(컴포넌트 방식으로 컨테이너가 관리)
    //https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter

    @Override
    protected void configure(HttpSecurity http) throws  Exception{
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin").access("\"hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }

     */
}
