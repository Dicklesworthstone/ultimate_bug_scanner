// GH #91 suppression fixture (bead A7) for the Java module, twin of
// suppression_buggy_nomarkers.java (identical buggy code, no markers).
// Every native java finding below (Statement/PreparedStatement/ResultSet
// acquired outside try-with-resources, Runtime.exec — the path:line code
// samples printed by the module) carries an ubs:ignore marker in one of the
// documented arrangements, so scanning this file must report zero findings,
// while the nomarkers twin reproduces them.

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class SuppressionBuggy {

    // Arrangement 1: previous-line marker.
    public void queryPrevLine(Connection conn) throws SQLException {
        // ubs:ignore -- fixture: marker on the line immediately above the finding
        Statement stmt = conn.createStatement();
        stmt.execute("SELECT 1");
    }

    // Arrangement 2: trailing marker on the flagged line itself.
    public void queryTrailing(Connection conn) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT 1"); // ubs:ignore -- fixture: trailing marker
        ps.execute();
    }

    // Arrangement 3: multi-line statement, marker on a continuation line.
    public void queryMultiline(Statement stmt) throws SQLException {
        ResultSet rs =
            stmt.executeQuery("SELECT 1"); // ubs:ignore -- fixture: marker on a physical line of a multi-line statement
    }

    // Arrangement 4: formatter-relocated marker on the first line inside a block.
    public void queryInBlock(Connection conn) throws SQLException {
        if (conn != null) { Statement guarded = conn.createStatement();
            // ubs:ignore -- fixture: formatter moved the marker inside the block
        }
    }

    // Arrangement 5: rule-scoped markers (ubs:ignore[rule]). Java code-sample
    // lines carry no rule id, so these suppress through the runner's
    // same-line/previous-line path.
    public void ruleScopedPrevLine(Connection conn) throws SQLException {
        // ubs:ignore[java.resource.statement-no-close] -- fixture: rule-scoped marker above the finding
        Statement scoped = conn.createStatement();
        scoped.execute("SELECT 1");
    }

    public void ruleScopedTrailing(Connection conn) throws SQLException {
        PreparedStatement scopedPs = conn.prepareStatement("SELECT 1"); // ubs:ignore[java.resource.statement-no-close] -- fixture: rule-scoped trailing marker
        scopedPs.execute();
    }

    // Arrangement 6: Runtime.exec critical, previous-line marker.
    public void runShell(String userInput) throws java.io.IOException {
        // ubs:ignore -- fixture: marker on the line immediately above the finding
        Runtime.getRuntime().exec(userInput);
    }
}
