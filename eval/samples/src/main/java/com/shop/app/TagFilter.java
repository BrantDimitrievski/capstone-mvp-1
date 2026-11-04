package com.shop.app;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

@WebServlet("/products/tag")
public class TagFilter extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String tag = req.getParameter("tag");
        if ("sale".equals(tag)) {
            tag = "sale";
        } else if ("new".equals(tag)) {
            tag = "new";
        } else {
            tag = "featured";
        }
        try (Connection conn = Db.get()) {
            Statement st = conn.createStatement();
            ResultSet rs = st.executeQuery("select name from products where tag = '" + tag + "'");
            while (rs.next()) {
                resp.getWriter().println(rs.getString(1));
            }
        } catch (SQLException e) {
            resp.sendError(500);
        }
    }
}
