import psycopg2

try:
    conn = psycopg2.connect(
        dbname="browns",
        user="postgres",
        password="1234",
        host="localhost",
        port="5432"
    )
    cur = conn.cursor()
    
    print("--- Users in database ---")
    cur.execute("SELECT id, email, role, is_active, account_status FROM users;")
    users = cur.fetchall()
    for user in users:
        print(user)
        
    cur.close()
    conn.close()
except Exception as e:
    print(f"Error: {e}")
