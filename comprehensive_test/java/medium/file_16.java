// Java test file 16 with vulnerabilities

import java.sql.*;
import java.io.*;
import javax.servlet.http.*;
import java.security.MessageDigest;

public class TestApp16 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // CWE-79: XSS
        String name = request.getParameter("name");
        if (name == null) name = "World";
        response.getWriter().println("<h1>Hello " + name + "!</h1>");  // VULNERABLE

        // CWE-89: SQL Injection
        String userId = request.getParameter("id");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "pass");
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE id = " + userId;  // VULNERABLE
            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                response.getWriter().println(rs.getString("name"));
            }
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }

        // CWE-78: Command Injection
        String cmd = request.getParameter("cmd");
        if (cmd != null) {
            try {
                Process process = Runtime.getRuntime().exec(cmd);  // VULNERABLE
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    response.getWriter().println(line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        // CWE-22: Path Traversal
        String filename = request.getParameter("file");
        if (filename != null) {
            File file = new File(filename);  // VULNERABLE
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                response.getWriter().println(line);
            }
            reader.close();
        }
    }
}
