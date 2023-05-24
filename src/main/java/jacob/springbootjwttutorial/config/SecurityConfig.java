package jacob.springbootjwttutorial.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity // 웹 보안 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests() // HttpServletRequest를 사용하는 요청들에 대한 접근제한 설정하겠다는 의미
                .antMatchers("/api/hello").permitAll() // 해당 api에 url에 인증 없이 접근 허용하겠다는 의미
                .anyRequest().authenticated();  // 나머지는 모두 인증 받아야 함
    }
}
