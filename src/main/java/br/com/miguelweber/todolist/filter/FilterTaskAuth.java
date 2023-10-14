package br.com.miguelweber.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.miguelweber.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var serveletPath = request.getServletPath();

        if (serveletPath.startsWith("/tasks/")) {
            // Pegar autenticacao (usuario e senha)
            var authorization = request.getHeader("Authorization");
            var auth_encoded = authorization.substring("Basic".length()).trim();

            byte[] auth_decoded = Base64.getDecoder().decode(auth_encoded);

            var auth_string = new String(auth_decoded);
            String[] credentials = auth_string.split(":");
            String username = credentials[0];
            String password = credentials[1];

            // Validar usuario
            var user = this.userRepository.findByUsername(username);
            if (user == null) {
                response.sendError(401);
            } else {
                // Validar senha
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if (passwordVerify.verified) {
                    // Segue viagem
                    request.setAttribute("userId", user.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401);
                }

            }
        } else {
            filterChain.doFilter(request, response);
        }

    }

}
