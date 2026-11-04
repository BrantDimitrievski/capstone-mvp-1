package com.shop.app;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileReader;
import java.io.IOException;
import java.io.BufferedReader;

@WebServlet("/admin/logs")
public class LogViewer extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        name = name.replace("../", "");
        try (BufferedReader r = new BufferedReader(new FileReader("/var/log/shop/" + name))) {
            String line;
            while ((line = r.readLine()) != null) {
                resp.getWriter().println(line);
            }
        }
    }
}
