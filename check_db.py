import mysql.connector

def inspect_database():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root123",
            database="infovault"
        )
        cursor = conn.cursor(dictionary=True)

        print("==================================================")
        print(" [DATABASE INSPECTOR] - INFOVAULT AI (MySQL)")
        print("==================================================")
        print("Connected successfully to database: 'infovault' on localhost\n")

        # 1. Users Table
        print("--- [TABLE: users] ---")
        cursor.execute("SELECT id, name, email, dark_mode, language, two_factor_enabled FROM users")
        users = cursor.fetchall()
        print(f"Total registered users: {len(users)}")
        for u in users:
            print(f"  * User #{u['id']}: {u['name']} | Email: {u['email']} | Language: {u['language']} | 2FA: {'Enabled' if u['two_factor_enabled'] else 'Disabled'} | Dark Mode: {'ON' if u['dark_mode'] else 'OFF'}")

        # 2. Documents Table
        print("\n--- [TABLE: documents] ---")
        cursor.execute("SELECT id, user_id, title, category, document_type, expiry_date, uploaded_at FROM documents ORDER BY uploaded_at DESC")
        documents = cursor.fetchall()
        print(f"Total vaulted documents: {len(documents)}")
        for d in documents:
            exp = str(d['expiry_date']) if d['expiry_date'] else 'No Expiry'
            print(f"  * Doc #{d['id']}: '{d['title']}' | Cat: {d['category']} | Type: {d['document_type']} | Expiry: {exp} | UserID: {d['user_id']}")

        # 3. Table Schema Columns
        print("\n--- [COLUMNS IN 'documents' TABLE] ---")
        cursor.execute("DESCRIBE documents")
        for col in cursor.fetchall():
            print(f"  - {col['Field']:<18} ({col['Type']})")

        print("\n--- [COLUMNS IN 'users' TABLE] ---")
        cursor.execute("DESCRIBE users")
        for col in cursor.fetchall():
            print(f"  - {col['Field']:<18} ({col['Type']})")

        print("\n==================================================")
        cursor.close()
        conn.close()

    except Exception as e:
        print("[ERROR] Error connecting to database:", e)
        print("Please ensure your MySQL service is started.")

if __name__ == "__main__":
    inspect_database()
