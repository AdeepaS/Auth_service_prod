UPDATE users SET password_hash = '$2a$10$8.UnVuG9HHgffUDAlk8q2OuVGkqEnLPzS47uvK706E49pA7qHOfn6' WHERE email = 'admin@example.com';
DELETE FROM login_attempts WHERE username = 'admin@example.com';
