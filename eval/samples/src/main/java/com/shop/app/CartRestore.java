package com.shop.app;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.List;

@WebServlet("/cart/restore")
public class CartRestore extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try (ObjectInputStream in = new ObjectInputStream(req.getInputStream())) {
            List<?> items = (List<?>) in.readObject();
            req.getSession().setAttribute("cart", items);
            resp.getWriter().println("restored " + items.size() + " items");
        } catch (ClassNotFoundException e) {
            resp.sendError(400);
        }
    }
}
