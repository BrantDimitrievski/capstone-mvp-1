package com.example.vulnlab;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.ObjectInputStream;

/** Seeded: CWE-502 deserialization of the raw request body. */
@WebServlet("/session/restore")
public class SessionRestoreServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try (ObjectInputStream in = new ObjectInputStream(request.getInputStream())) {
            Object state = in.readObject();
            request.getSession().setAttribute("state", state);
        } catch (ClassNotFoundException e) {
            response.sendError(400);
        }
    }
}
