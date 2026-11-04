package com.shop.app;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

@WebServlet("/theme.css")
public class ThemeLoader extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String theme = req.getParameter("theme");
        String file;
        switch (theme == null ? "" : theme) {
            case "dark":
                file = "/var/shop/themes/dark.css";
                break;
            case "contrast":
                file = "/var/shop/themes/contrast.css";
                break;
            default:
                file = "/var/shop/themes/light.css";
        }
        try (InputStream in = new FileInputStream(file)) {
            resp.getOutputStream().write(in.readAllBytes());
        }
    }
}
