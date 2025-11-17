import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;

public class CleanSecurity {
    public void safeQuery(String user) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        stmt.setString(1, user);
        stmt.execute();
        new ProcessBuilder("ls", user).start();
    }
}
