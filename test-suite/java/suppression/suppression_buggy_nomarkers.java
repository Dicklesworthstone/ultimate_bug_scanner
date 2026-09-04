// GH #91 suppression fixture (bead A7) for the Java module, twin of
// suppression_buggy.java: identical buggy code with every ubs:ignore marker
// removed, so a scan of this file must reproduce the native java findings
// (Statement/PreparedStatement/ResultSet acquired outside try-with-resources,
// Runtime.exec) that the markered twin suppresses.

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class SuppressionBuggy {

    // Arrangement 1: previous-line marker goes immediately above this finding.
    public void queryPrevLine(Connection conn) throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.execute("SELECT 1");
    }

    // Arrangement 2: trailing marker belongs on this flagged line itself.
    public void queryTrailing(Connection conn) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT 1");
        ps.execute();
    }

    // Arrangement 3: multi-line statement; marker belongs on a continuation line.
    public void queryMultiline(Statement stmt) throws SQLException {
        ResultSet rs =
            stmt.executeQuery("SELECT 1");
    }

    // Arrangement 4: formatter-relocated marker belongs on the first line
    // inside the block whose opening line is flagged.
    public void queryInBlock(Connection conn) throws SQLException {
        if (conn != null) { Statement guarded = conn.createStatement();
        }
    }

    // Arrangement 5: rule-scoped markers (ubs:ignore[rule]). Java code-sample
    // lines carry no rule id, so these suppress through the runner's
    // same-line/previous-line path.
    public void ruleScopedPrevLine(Connection conn) throws SQLException {
        Statement scoped = conn.createStatement();
        scoped.execute("SELECT 1");
    }

    public void ruleScopedTrailing(Connection conn) throws SQLException {
        PreparedStatement scopedPs = conn.prepareStatement("SELECT 1");
        scopedPs.execute();
    }

    // Arrangement 6: Runtime.exec critical; previous-line marker goes above.
    public void runShell(String userInput) throws java.io.IOException {
        Runtime.getRuntime().exec(userInput);
    }
}
