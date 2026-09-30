package com.example.vulnlab;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/** Seeded: CWE-78 OS command injection from the "host" request parameter. */
@WebServlet("/ping")
public class PingServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String host = request.getParameter("host");
        Process process = Runtime.getRuntime().exec("ping -c 1 " + host);
        response.getOutputStream().write(process.getInputStream().readAllBytes());
    }

    /** Constant command: must not be flagged. */
    String uptime() throws IOException {
        Process p = new ProcessBuilder("uptime").start();
        return new String(p.getInputStream().readAllBytes());
    }
}
