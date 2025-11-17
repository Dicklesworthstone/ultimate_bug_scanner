import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class BuggySecurity {
    public void insecureQuery(String user) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
        while (rs.next()) {
            System.out.println(rs.getString(1));
        }
        Runtime.getRuntime().exec("sh -c 'ls '" + user);
    }
}
