import java.sql.Statement;

public class TestJava {
    public void run(Statement stmt, String input) throws Exception {
        // ruleid: java-sql-injection
        stmt.executeQuery("SELECT * FROM users WHERE name = " + input);

        // ruleid: java-command-injection
        Runtime.getRuntime().exec(input);
    }
}
