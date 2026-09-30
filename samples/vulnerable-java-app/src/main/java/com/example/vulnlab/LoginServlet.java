package com.example.vulnlab;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/** Seeded: CWE-89 SQL injection from request parameters, CWE-798 hard-coded database password. */
@WebServlet("/login")
public class LoginServlet extends HttpServlet {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/vulnlab";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        try (Connection conn = DriverManager.getConnection(DB_URL, "root", "S3cr3tP@ssw0rd!")) {
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            ResultSet rs = stmt.executeQuery(query);
            if (rs.next()) {
                request.getSession().setAttribute("user", username);
                response.sendRedirect("/home");
            } else {
                response.sendError(401, "Invalid credentials");
            }
        } catch (SQLException e) {
            e.printStackTrace();
            response.sendError(500);
        }
    }
}
