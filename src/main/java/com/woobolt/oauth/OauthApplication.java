package com.woobolt.oauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.stream.Stream;

@SpringBootApplication
public class OauthApplication {

	public static void main(String[] args) {
		SpringApplication.run(OauthApplication.class, args);
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()));
		http.oauth2Login(Customizer.withDefaults());

		return http
				.authorizeHttpRequests(c -> c.requestMatchers("/error").permitAll()
						.requestMatchers("/manager.html").hasRole("MANAGER")
						.anyRequest().authenticated())
				.build();
	}

	/*jwtAuthenticationConverter():
	Этот метод конфигурирует JwtAuthenticationConverter, который используется для преобразования JWT (JSON Web Token)
	в объект аутентификации Spring Security.
	Внутри метода устанавливается имя главного клейма (principal claim) в JWT с помощью
	setPrincipalClaimName("preferred_username"). Это означает, что при аутентификации Spring Security будет
	использовать значение, указанное в клейме "preferred_username", в качестве имени пользователя (principal).
	В методе setJwtGrantedAuthoritiesConverter() настраивается конвертер, который извлекает роли и полномочия из JWT и
	добавляет их к объекту аутентификации Spring Security.
	Роли извлекаются из клейма "spring-security-role" в JWT. Затем они фильтруются и преобразуются в объекты
	SimpleGrantedAuthority, представляющие роли пользователя в Spring Security.*/
	@Bean
	public JwtAuthenticationConverter jwtAuthenticationConverter() {
		var converter = new JwtAuthenticationConverter();
		var jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		converter.setPrincipalClaimName("preferred_username");
		converter.setJwtGrantedAuthoritiesConverter(jwt -> {
			var authorities = jwtGrantedAuthoritiesConverter.convert(jwt); // ArrayList of authorities
			var roles = jwt.getClaimAsStringList("spring-security-role");

			return Stream.concat(authorities.stream(),
							roles.stream()
								.filter(role -> role.startsWith("ROLE_"))
								.map(SimpleGrantedAuthority::new)
								.map(SimpleGrantedAuthority.class::cast))
							.toList();
		});

		return converter;
	}

	/*oAuth2UserService():
	Этот метод конфигурирует OAuth2UserService, который используется для загрузки информации о пользователе при
	использовании протокола OIDC.
	Внутри метода используется стандартный OidcUserService, который загружает информацию о пользователе из OIDC
	провайдера.
	Затем производится обработка информации о пользователе, включая его роли. Роли извлекаются из клейма
	"spring-security-role" в OIDC пользователе.
	Аналогично первому методу, роли фильтруются и преобразуются в объекты SimpleGrantedAuthority.*/
	@Bean // more about OidcProvider
	public OAuth2UserService<OidcUserRequest, OidcUser> oAuth2UserService() {
		var oidcUserService = new OidcUserService();
		return userRequest -> {
			var oidcUser = oidcUserService.loadUser(userRequest);
			var roles = oidcUser.getClaimAsStringList("spring-security-roles"); // User roles mapper of roles
			var authorities = Stream.concat(oidcUser.getAuthorities().stream(),
					roles.stream()
							.filter(role -> role.startsWith("ROLE_"))
							.map(SimpleGrantedAuthority::new)
							.map(SimpleGrantedAuthority.class::cast))
					.toList();

			return new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
		};
	}
	/*	основное отличие между этими двумя методами заключается в том, что первый метод (jwtAuthenticationConverter())
	работает с JWT, в то время как второй метод (oAuth2UserService()) работает с OIDC. Они оба выполняют преобразование
	информации о ролях пользователя в объекты SimpleGrantedAuthority, но работают с разными типами токенов и провайдерами.*/
}

/*
JwtAuthenticationConverter jwtAuthenticationConverter(): Этот метод создает и возвращает экземпляр
JwtAuthenticationConverter. Этот конвертер будет использоваться для преобразования JWT в
объект аутентификации Spring Security.

converter.setPrincipalClaimName("preferred_username"): Устанавливает имя принципала (пользователя) в JWT.
В данном случае, предполагается, что в поле preferred_username JWT содержит имя пользователя,
которое будет использоваться как принципал.

converter.setJwtGrantedAuthoritiesConverter(...): Устанавливает конвертер для извлечения ролей и полномочий из JWT.
Внутри этого метода определяется функция конвертации, которая принимает JWT в качестве входного параметра и
возвращает список объектов GrantedAuthority, представляющих роли пользователя.

var roles = (List<String>) jwt.getClaimAsMap("realm-access").get("roles"): Получает список ролей из JWT. Обычно роли
содержатся в определенном разделе или клейме JWT. Здесь предполагается, что роли хранятся в клейме realm-access.

return Stream.concat(authorities.stream(), roles.stream()...): Этот блок кода соединяет уже имеющиеся полномочия
(например, роли, полученные из стандартного конвертера) с ролями, извлеченными непосредственно из JWT.
Роли извлекаются из списка ролей JWT, фильтруются на предмет тех, которые начинаются с "ROLE_", и преобразуются в
объекты SimpleGrantedAuthority. Затем они объединяются с уже имеющимися полномочиями и возвращаются как итоговый
список полномочий.

В контексте аутентификации и авторизации с помощью JWT (JSON Web Token), термин "claim" относится к информации,
содержащейся в самом токене. JWT состоит из набора claim'ов, которые представляют собой утверждения о пользователе
или о субъекте, для которого создан токен. Каждый claim представляет собой пару "имя"-"значение".

В методе, который вы предоставили, jwt.getClaimAsMap("realm-access").get("roles") используется для получения значений
из claim'а с именем "realm-access". Обычно такие claim'ы содержат дополнительную информацию о ролях или правах
доступа пользователя, которые могут использоваться для определения того, какие действия пользователь может выполнять
в приложении.

В вашем конкретном случае, вероятно, claim "realm-access" содержит список ролей, присвоенных пользователю. Вы
используете этот claim, чтобы извлечь роли пользователя и преобразовать их в объекты SimpleGrantedAuthority, которые
в Spring Security используются для представления прав доступа пользователя.

Итак, в данном контексте "claim" представляет собой часть информации, содержащейся в JWT, которая используется для
аутентификации и авторизации пользователя в вашем приложении.
*/
