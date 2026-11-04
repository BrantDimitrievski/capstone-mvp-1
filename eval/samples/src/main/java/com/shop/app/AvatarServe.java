package com.shop.app;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@WebServlet("/avatars")
public class AvatarServe extends HttpServlet {

    private static final Path BASE = Paths.get("/var/shop/avatars").toAbsolutePath().normalize();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("img");
        Path p = BASE.resolve(name).normalize();
        if (!p.startsWith(BASE)) {
            resp.sendError(403);
            return;
        }
        resp.getOutputStream().write(Files.readAllBytes(p));
    }
}
