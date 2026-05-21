import bcrypt
import psycopg2

password = "admin123"
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

try:
    conn = psycopg2.connect(
        dbname="browns",
        user="postgres",
        password="1234",
        host="localhost",
        port="5432"
    )
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = %s WHERE email = 'admin@example.com';", (hashed,))
    conn.commit()
    print(f"Updated admin@example.com with hash: {hashed}")
    cur.close()
    conn.close()
except Exception as e:
    print(f"Error: {e}")
