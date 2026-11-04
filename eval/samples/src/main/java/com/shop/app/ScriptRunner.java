package com.shop.app;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/admin/jobs/run")
public class ScriptRunner extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String job = req.getParameter("job");
        resp.getWriter().println(runJob(job));
    }

    private String runJob(String name) throws IOException {
        String cmd = "/opt/shop/jobs/" + name + ".sh";
        Process p = new ProcessBuilder("sh", "-c", cmd).start();
        return new String(p.getInputStream().readAllBytes());
    }
}
