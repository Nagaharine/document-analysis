import mysql.connector
import sys

def interactive_sql_terminal():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root123",
            database="infovault"
        )
        cursor = conn.cursor()
        print("==================================================")
        print(" INFOVAULT AI - Interactive SQL Console")
        print(" Connected to 'infovault' database (MySQL)")
        print(" Type 'exit' or 'quit' to close.")
        print("==================================================")

        while True:
            try:
                query = input("\ninfovault-sql> ").strip()
                if not query:
                    continue
                if query.lower() in ["exit", "quit"]:
                    print("Goodbye!")
                    break

                cursor.execute(query)

                if query.lower().startswith("select") or query.lower().startswith("show") or query.lower().startswith("describe"):
                    rows = cursor.fetchall()
                    columns = [d[0] for d in cursor.description] if cursor.description else []
                    
                    if not rows:
                        print("Empty set (0 rows).")
                    else:
                        print(" | ".join(f"{c:<20}" for c in columns))
                        print("-" * (22 * len(columns)))
                        for r in rows:
                            print(" | ".join(f"{str(v):<20}" for v in r))
                        print(f"\n({len(rows)} row(s) returned)")
                else:
                    conn.commit()
                    print(f"Query OK, {cursor.rowcount} row(s) affected.")

            except Exception as q_err:
                print(f"[SQL Error]: {q_err}")

        cursor.close()
        conn.close()

    except Exception as e:
        print("[Database Connection Error]:", e)

if __name__ == "__main__":
    interactive_sql_terminal()
