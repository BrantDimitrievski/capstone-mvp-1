package com.shop.app;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/admin/archive")
public class ArchiveJob extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String month = req.getParameter("month");
        if (month == null || !month.matches("[0-9]{4}-[0-9]{2}")) {
            resp.sendError(400);
            return;
        }
        new ProcessBuilder("tar", "-czf", "/backups/orders-" + month + ".tgz", "/var/shop/orders/" + month).start();
        resp.getWriter().println("started");
    }
}
