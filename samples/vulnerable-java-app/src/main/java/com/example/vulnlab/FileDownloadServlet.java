package com.example.vulnlab;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/** Seeded: CWE-22 path traversal from the "file" request parameter. */
@WebServlet("/download")
public class FileDownloadServlet extends HttpServlet {

    private static final String BASE_DIR = "/var/app/uploads/";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        File file = new File(BASE_DIR + fileName);
        if (!file.exists()) {
            response.sendError(404);
            return;
        }
        response.setContentType("application/octet-stream");
        Files.copy(file.toPath(), response.getOutputStream());
    }
}
