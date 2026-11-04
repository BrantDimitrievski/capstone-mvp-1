package com.shop.app;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

@WebServlet("/attachments")
public class AttachmentDownload extends HttpServlet {

    private static final String DIR = "/var/shop/attachments";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("file");
        File f = new File(DIR, name);
        resp.getOutputStream().write(Files.readAllBytes(f.toPath()));
    }
}
