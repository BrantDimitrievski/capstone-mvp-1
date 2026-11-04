package com.shop.app;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/admin/ping")
public class HostCheck extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String host = req.getParameter("host");
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        resp.getWriter().println(new String(p.getInputStream().readAllBytes()));
    }
}
