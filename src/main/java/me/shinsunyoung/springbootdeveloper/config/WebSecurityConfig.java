package me.shinsunyoung.springbootdeveloper.config;

import lombok.RequiredArgsConstructor;
import me.shinsunyoung.springbootdeveloper.service.UserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {


    private final UserDetailService userService;


    // 스프링 시큐리티 기능 비활성화(모든 기능을 사용하지 않는다는 의미)
    @Bean
    public WebSecurityCustomizer configure() {
        return (web) -> web.ignoring()
                 //.requestMatchers(toH2Console()) // H2 콘솔
                .requestMatchers(new AntPathRequestMatcher("/static/**")); // 정적 파일
    }

    // 특정 HTTP 요청에 대한 보안 규칙
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests(auth -> auth // 인증, 인가(권한) 설정
                        .requestMatchers(
                                new AntPathRequestMatcher("/login"),
                                new AntPathRequestMatcher("/signup"),
                                new AntPathRequestMatcher("/user")
                        ).permitAll() // 인증 없이 접근 가능한 경로들
                        .anyRequest().authenticated()) // 나머지 모든 요청은 인증된 사용자만 접근 가능
                .formLogin(formLogin -> formLogin // 폼 기반 로그인
                        .loginPage("/login") // 로그인하지 않은 상태의 경로(로그인 페이지)
                        .defaultSuccessUrl("/articles") // 로그인 성공 시 이동할 경로
                )
                .logout(logout -> logout // 로그아웃 설정
                        .logoutSuccessUrl("/login") // 로그아웃 성공 후 경로(로그인 페이지)
                        .invalidateHttpSession(true) // 로그아웃시 현재 세션 무효화(보안 강화)
                )
                .csrf(AbstractHttpConfigurer::disable) // csrf 비활성화(개발 중), 보통은 보호를 활성화 함
                .build();
    }

    // 인증 관리자 관련 설정
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, BCryptPasswordEncoder bCryptPasswordEncoder, UserDetailService userDetailService) throws Exception {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userService); // 사용자 정보 제공
        authProvider.setPasswordEncoder(bCryptPasswordEncoder); // 비밀번호 비교(암호화)
        return new ProviderManager(authProvider);
    }

    // 비밀번호 인코더로 사용, 비밀번호 암호화 후 비교
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
