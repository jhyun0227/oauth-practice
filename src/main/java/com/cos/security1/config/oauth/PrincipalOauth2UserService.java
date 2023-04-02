package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.entity.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final UserRepository userRepository;

    //구글로부터 받은 userRequest 데이터에 대한 후처리 되는 함수
    //회원가입을 강제로 진행
    //함수 종료 시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        //registrationId로 어떤 Oauth 로그인했는지 확인 가능
        System.out.println("getClientRegistration = " + userRequest.getClientRegistration());
        System.out.println("getAccessToken = " + userRequest.getAccessToken().getTokenValue());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        //구글로그인 버튼 클릭 -> 구글 로그인창 -> 로그인 완료 -> code를 리턴(OAuth-Client라이브러리) -> AccessToken 요청
        //userRequest 정보 -> loadUser 함수 -> 구글로부터 회원프로필 받아준다.
        System.out.println("getAttributes = " + oAuth2User.getAttributes());

        //회원가입을 강제로 진행
        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            oAuth2UserInfo = new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId; //google_114610520353030138266
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        Optional<User> findUser = userRepository.findByUsername(username);

        if (findUser.isEmpty()) {
            System.out.println("로그인이 최초입니다.");
            User user = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();

            userRepository.save(user);

            return new PrincipalDetails(user, oAuth2User.getAttributes());
        } else {
            System.out.println("로그인을 한 적이 있습니다.");
        }

        return null;
    }
}
