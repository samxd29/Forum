package br.com.alura.forum.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.alura.forum.config.security.TokenService;
import br.com.alura.forum.controller.dto.TokenDto;
import br.com.alura.forum.controller.form.LoginForm;

@RestController
@RequestMapping("/auth")
public class AutenticacaoController {
	
	@Autowired //Olhar a classe securityConfguration
	private AuthenticationManager authManager; //Essa classe é do Spring mais não consegue fazer a injeção de dependencia automaticamente;
	
	@Autowired
	private TokenService tokenService;
	
	//E esse método vai ser chamado se a requisição for /auth, e via método @PostMapping. 
	//Como é autenticação, estou recebendo parâmetros de usuário e senha, preciso que seja via método post.
	@PostMapping
	public ResponseEntity<TokenDto> autenticar(@RequestBody @Valid LoginForm form) {
	    UsernamePasswordAuthenticationToken dadosLogin = form.converter();

	    try{
	        Authentication authentication = authManager.authenticate(dadosLogin);
	        String token = (tokenService).gerarToken(authentication);
	        return ResponseEntity.ok(new TokenDto(token, "Bearer"));//Bearer é um dos mecanismos de autenticação utilizados no protocolo HTTP, tal como o Basic e o Digest.
	    } catch (AuthenticationException e) {
	        return ResponseEntity.badRequest().build();
	    }

	}
}