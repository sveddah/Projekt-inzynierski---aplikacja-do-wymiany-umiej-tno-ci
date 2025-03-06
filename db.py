import sqlite3

connection = sqlite3.connect('database.db')
cursor = connection.cursor()

def create_tables():
    connection = sqlite3.connect('database.db')
    cursor = connection.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            city TEXT NOT NULL,
            join_date DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS skills (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            skill_name TEXT NOT NULL,
            description TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            offer_id INTEGER, 
            conversation_id TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            exchange_status TEXT DEFAULT NULL,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id),
            FOREIGN KEY (offer_id) REFERENCES skills (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS exchange_proposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            skill_id INTEGER NOT NULL,
            proposer_id INTEGER NOT NULL,
            proposed_skill_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY (skill_id) REFERENCES skills (id),
            FOREIGN KEY (proposer_id) REFERENCES users (id),
            FOREIGN KEY (proposed_skill_id) REFERENCES skills (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL, 
            comment TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (author_id) REFERENCES users (id)
        )
    ''')

    connection.commit()
    connection.close()