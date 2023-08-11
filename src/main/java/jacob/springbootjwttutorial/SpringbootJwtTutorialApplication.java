package jacob.springbootjwttutorial;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = {"org.springframework.web.filter.CorsFilter"})
public class SpringbootJwtTutorialApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringbootJwtTutorialApplication.class, args);
	}

}
