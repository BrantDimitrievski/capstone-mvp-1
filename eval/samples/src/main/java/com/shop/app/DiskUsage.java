package com.shop.app;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

@WebServlet("/admin/disk")
public class DiskUsage extends HttpServlet {

    private static final Logger LOG = Logger.getLogger("disk");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String who = req.getParameter("requestedBy");
        LOG.info("disk check requested by " + who);
        Process p = new ProcessBuilder("df", "-h", "/var/shop").start();
        resp.getWriter().println(new String(p.getInputStream().readAllBytes()));
    }
}
