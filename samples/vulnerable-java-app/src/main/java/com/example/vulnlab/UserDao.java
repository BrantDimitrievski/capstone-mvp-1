package com.example.vulnlab;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/** Seeded: CWE-89 via a method parameter. {@link #findByIdSafe} is the secure version and must not be flagged. */
public class UserDao {

    private final Connection connection;

    public UserDao(Connection connection) {
        this.connection = connection;
    }

    public ResultSet searchByName(String name) throws SQLException {
        String sql = "SELECT id, username, email FROM users WHERE username LIKE '%" + name + "%'";
        return connection.createStatement().executeQuery(sql);
    }

    public ResultSet findByIdSafe(long id) throws SQLException {
        PreparedStatement ps = connection.prepareStatement("SELECT id, username, email FROM users WHERE id = ?");
        ps.setLong(1, id);
        return ps.executeQuery();
    }
}
