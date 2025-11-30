import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

public class HelloWorldServer {
    public static void main(String[] args) throws IOException {
        int port = 8000;
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);

        // 🔹 Registramos el contexto EXACTO que queremos usar
        server.createContext("/jsm0058", new HelloHandler());
        server.createContext("/jsm0058/", new HelloHandler());
        server.setExecutor(null); // Usa el executor por defecto
        server.start();

        System.out.println("Servidor iniciado en http://localhost:" + port + "/jsm0058");
    }

    static class HelloHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "Hello jsm0058@alu.medac.es!";
            exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
            exchange.sendResponseHeaders(200, response.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }
    }
}
