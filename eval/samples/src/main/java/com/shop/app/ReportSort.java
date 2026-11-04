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

@WebServlet("/reports/sales")
public class ReportSort extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String sort = req.getParameter("sort");
        if (sort == null || sort.length() > 40) {
            sort = "created";
        }
        try (Connection conn = Db.get()) {
            Statement st = conn.createStatement();
            ResultSet rs = st.executeQuery("select region, total from sales order by " + sort);
            while (rs.next()) {
                resp.getWriter().println(rs.getString(1) + "," + rs.getDouble(2));
            }
        } catch (SQLException e) {
            resp.sendError(500);
        }
    }
}
