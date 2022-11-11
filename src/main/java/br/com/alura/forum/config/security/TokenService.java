package br.com.alura.forum.config.security;

import java.util.Date;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import br.com.alura.forum.modelo.Usuario;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class TokenService {
	
	@Value("${forum.jwt.expiration}") // pegar valor do aplication properties
	private String expiration;
	
	@Value("${forum.jwt.secret}") // pegar valor do aplication properties
	private String secret;

	//Criando um token;
	public String gerarToken(Authentication authentication) {
		Usuario logado = (Usuario) authentication.getPrincipal(); //Esse authentication tem um método chamado getPrincipal para conseguirmos recuperar o usuário que está logado
		Date hoje = new Date();
		Date dataExpiration = new Date(hoje.getTime() + Long.parseLong(expiration)); //Eu estou somando os milisegundo da data hoje com e acrescentando mais os milisegundos da expiration;
		return Jwts.builder()
				.setIssuer("Api do Fórum da Alura") //Quem está fazendo a requisição;
				.setSubject(logado.getId().toString())//quem é o dono desse token
				.setIssuedAt(hoje)
				.setExpiration(dataExpiration)
				.signWith(SignatureAlgorithm.HS256, secret)
				.compact();
	}

	//Método para descriptografar o token e conferir se é igual;
    public boolean isTokenValido(String token) {

		try {
			Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token);
			return true;
		}catch (Exception e) {
			return false;
		}
    }

	public Long getIdUsuario(String token) {
		//Método para pegar o Id do Usuário;
		Claims claims = Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token).getBody();
		return Long.parseLong(claims.getSubject());
	}
}
