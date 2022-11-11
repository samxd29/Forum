package br.com.alura.forum.config.security;

import br.com.alura.forum.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
public class SecurityConfigurations extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private AutenticacaoService autenticacaoService;
	@Autowired
	private UsuarioRepository usuarioRepository;

	@Autowired
	private TokenService tokenService;
	
	//A classe que a gente já está extendendo tem o método do AuthenticationManager
	@Override
	@Bean //em cima do método, porque o Spring saberá que esse método devolve o authenticationManager e conseguimos injetar no nosso controller.
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}
	
	//Configurações de login, controle de acesso
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//Passamos no userDetails uma classe de service que ttem a lógica do controle de acesso.
		//password vai ser encriptado pelo Spring
		auth.userDetailsService(autenticacaoService).passwordEncoder(new BCryptPasswordEncoder());
	}
	
	//Configurações de recursos staticos(js, css, imagens...)
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/**.html", "/v2/api-docs", "/webjars/**","/configuration/**", "/swagger-resources/**");

	}
	
	//Configurações de Autorizações, perfis de acesso
	@SuppressWarnings("unchecked")
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers(HttpMethod.GET, "/topicos").permitAll()
				.antMatchers(HttpMethod.GET, "/topicos/*").permitAll()
				.antMatchers(HttpMethod.POST, "/auth").permitAll()
				.antMatchers(HttpMethod.GET, "/actuator/**").permitAll()//quando for colocar em produção tirar o permite all
				.anyRequest().authenticated() //qualquer outra requisição tem que estar autenticada;
				//.and().formLogin(); //Spring gerar um formulário de autenticação
				.and().csrf().disable() //Csrf é uma abreviação para cross-site request forgery, que é um tipo de ataque hacker que acontece em aplicações web
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//Com isso, aviso para o Spring security que no nosso projeto, quando eu fizer autenticação, não é para criar sessão, porque vamos usar token.
				.and().addFilterBefore(new AutenticacaoViaTokenFilter(tokenService, usuarioRepository), UsernamePasswordAuthenticationFilter.class);
	}
	
	

}
