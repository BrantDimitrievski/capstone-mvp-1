package com.shop.app;

import java.util.Properties;

public class MailClient {

    private static final String SMTP_USER = "orders@shop.local";
    private static final String SMTP_PASSWORD = "Wint3r!Sale2026";

    public static Properties settings() {
        Properties p = new Properties();
        p.put("mail.smtp.host", "smtp.shop.local");
        p.put("mail.smtp.user", SMTP_USER);
        p.put("mail.smtp.password", SMTP_PASSWORD);
        return p;
    }
}
