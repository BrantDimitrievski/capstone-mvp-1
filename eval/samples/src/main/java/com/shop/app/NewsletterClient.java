package com.shop.app;

import java.util.Properties;

public class NewsletterClient {

    public static Properties settings() {
        Properties p = new Properties();
        p.put("mail.smtp.host", "smtp.shop.local");
        p.put("mail.smtp.user", System.getenv("NEWSLETTER_USER"));
        p.put("mail.smtp.password", System.getenv("NEWSLETTER_PASSWORD"));
        return p;
    }
}
