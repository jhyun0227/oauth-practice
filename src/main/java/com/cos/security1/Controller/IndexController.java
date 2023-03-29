package com.cos.security1.Controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.entity.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.time.LocalDateTime;

@Controller
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;


    /**
     *  Session 안에 Security Session이 존재하고 그 안에 Authentication이 존재하며 그 안에 UserDetails(일반적로그인)와 OAuth2User(소셜로그인) 객체가 존재한다.
     */
    @GetMapping("/test/login")
    @ResponseBody
    //일반 로그인
    //두가지중 편한 방법으로.... 같은 데이터임
    public String testLogin(Authentication authentication, @AuthenticationPrincipal PrincipalDetails principalDetails2) {
        System.out.println("/test/login ====================");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication = " + principalDetails.getUser());

        System.out.println("userDetails = " + principalDetails2.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    @ResponseBody
    //oauth 로그인
    //두가지중 편한 방법으로.... 같은 데이터임
    public String testOAuthLogin(Authentication authentication, @AuthenticationPrincipal OAuth2User oAuth2User2) {
        System.out.println("/test/login ====================");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication = " + oAuth2User.getAttributes());

        System.out.println("oAuth2User2 = " + oAuth2User2.getAttributes());

        return "OAuth 세션 정보 확인하기";
    }

    //이렇게 Authentication에 두 개의 객체가 존재하기 때문에, 로그인 시에 파라미터 주입이 까다롭다.
    //그렇기 때문에 PrincipalDetails에 두 개의 객체를 상속받아 합쳐준다. 그렇게 되면 파라미터 주입이 간단해진다.

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    //일반로그인, OAuth 로그인 둘다 principalDeatails로 받을수 있다.
    @GetMapping("/user")
    @ResponseBody
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails = " + principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager() {
        return "manager";
    }

    //Spring Security 처음 설정 후에는 해당 주소를 낚아챈다.
    //SecurityConfig 파일 생성 후 작동X
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        System.out.println("user = " + user);

        user.setRole("ROLE_USER");
        user.setCreateDate(LocalDateTime.now());

        //비밀번호 암호화를 하지 않아도 회원가입은 잘되지만 시큐리티 로그인은 할 수없다.
        //그렇기 때문에 암호화는 필수이다.
        String encodePassword = encoder.encode(user.getPassword());
        user.setPassword(encodePassword);

        userRepository.save(user);

        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    @ResponseBody
    public String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") //메소드 실행전에 실행된다.
//    @PostAuthorize() //메소드 실행후 실행된다. 자주 쓸일은 없다.
    @GetMapping("/data")
    @ResponseBody
    public String data() {
        return "데이터정보";
    }
}
