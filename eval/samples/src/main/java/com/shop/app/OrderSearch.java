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

@WebServlet("/orders/search")
public class OrderSearch extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String customer = req.getParameter("customer");
        try (Connection conn = Db.get()) {
            Statement st = conn.createStatement();
            ResultSet rs = st.executeQuery("select id, total from orders where customer = '" + customer + "'");
            while (rs.next()) {
                resp.getWriter().println(rs.getInt(1) + "," + rs.getDouble(2));
            }
        } catch (SQLException e) {
            resp.sendError(500);
        }
    }
}
