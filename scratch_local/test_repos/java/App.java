import java.sql.*;
public class App {
    public static void main(String[] args) throws Exception {
        String secret = "AWS_SECRET_KEY=123456789";
        String user = args[0];
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "user", "pass");
        conn.createStatement().execute("SELECT * FROM users WHERE username = '" + user + "'"); // SQLi
    }
}
