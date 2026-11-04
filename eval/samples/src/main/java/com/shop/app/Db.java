package com.shop.app;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Db {

    public static Connection get() throws SQLException {
        String url = System.getenv("SHOP_DB_URL");
        String user = System.getenv("SHOP_DB_USER");
        String pass = System.getenv("SHOP_DB_PASS");
        return DriverManager.getConnection(url, user, pass);
    }
}
