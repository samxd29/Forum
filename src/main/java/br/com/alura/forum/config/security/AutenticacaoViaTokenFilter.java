package br.com.alura.forum.config.security;

import br.com.alura.forum.modelo.Usuario;
import br.com.alura.forum.repository.UsuarioRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//Essa classe vai interceptar uma requisição e vai autenticar o token do cliente;

public class AutenticacaoViaTokenFilter extends OncePerRequestFilter{//Essa extensão é um filtro do Spring chamado uma única vez a cada requisição;
	//Nesse tipo de classe não conseguimos fazer injeção de dependências.
	//Não dá para colocar um @AutoWired, até porque na classe de SecurityConfiguration nós que instanciamos manualmente a classe.
	private TokenService tokenService;

	private UsuarioRepository usuarioRepository;

	public AutenticacaoViaTokenFilter(TokenService tokenService, UsuarioRepository usuarioRepository) {
		this.tokenService = tokenService;
		this.usuarioRepository = usuarioRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		//Criar um método privado para recuperar o token;
		String token = recuperarToken(request);
		boolean valido = tokenService.isTokenValido(token);
		if (valido) {
			autenticarCliente(token);
		}
		//Para falar que já rodamos o que tinha que rodar e para seguir em frente.
		filterChain.doFilter(request, response);
	}

	private void autenticarCliente(String token) {
		//Método para falar pro Spring para autenticar o usuario;
		Long idUsuario = tokenService.getIdUsuario(token);
		Usuario usuario= usuarioRepository.findById(idUsuario).get();
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	private String recuperarToken(HttpServletRequest request) {
    	//Nessa requição passo o nome que eu quero recuperar que é do postman.
    	String token = request.getHeader("Authorization");

    	if (token == null || token.isEmpty() || !token.startsWith("Bearer ")) {
			return null;
		}
    	//Pegar o token a partir do bearer, contamos 7 espaços na palavra bearer;
    	 return token.substring(7, token.length());
    } 

}
