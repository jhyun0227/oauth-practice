package com.cos.security1.Controller;

import com.cos.security1.entity.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
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

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    @GetMapping("/user")
    @ResponseBody
    public String user() {
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
