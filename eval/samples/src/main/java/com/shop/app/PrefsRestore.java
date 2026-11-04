package com.shop.app;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.util.HashMap;

@WebServlet("/prefs/restore")
public class PrefsRestore extends HttpServlet {

    private static final ObjectInputFilter ONLY_MAPS =
            ObjectInputFilter.Config.createFilter("java.util.HashMap;java.lang.String;!*");

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try (ObjectInputStream in = new ObjectInputStream(req.getInputStream())) {
            in.setObjectInputFilter(ONLY_MAPS);
            HashMap<?, ?> prefs = (HashMap<?, ?>) in.readObject();
            req.getSession().setAttribute("prefs", prefs);
            resp.getWriter().println("ok");
        } catch (ClassNotFoundException e) {
            resp.sendError(400);
        }
    }
}
