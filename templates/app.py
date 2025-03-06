from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from db import create_tables  # Importujemy funkcję create_tables
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Tworzymy tabele przy starcie aplikacji
create_tables()

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    search_query = request.args.get('search', '')
    city_query = request.args.get('city', '')
    
    conn = get_db_connection()
    
    if search_query or city_query:
        skills = conn.execute('''
            SELECT skills.*, users.username, users.city as user_city
            FROM skills
            JOIN users ON skills.user_id = users.id
            WHERE skill_name LIKE ? AND users.city LIKE ?
        ''', ('%' + search_query + '%', '%' + city_query + '%')).fetchall()
    else:
        skills = conn.execute('''
            SELECT skills.*, users.username, users.city as user_city
            FROM skills
            JOIN users ON skills.user_id = users.id
        ''').fetchall()
    
    conn.close()
    return render_template('index.html', skills=skills)

from datetime import datetime  # Upewnij się, że importujesz datetime

@app.route('/details')
def account_details():
    if not session.get('username'):
        flash('Musisz się zalogować, aby zobaczyć tę stronę.', 'error')
        return redirect(url_for('account'))
    
    # Pobierz dane użytkownika z bazy danych
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    
    if not user:
        flash('Użytkownik nie istnieje.', 'error')
        return redirect(url_for('index'))
    
    # Przekształć join_date na obiekt datetime
    join_date = datetime.strptime(user['join_date'], '%Y-%m-%d %H:%M:%S')
    
    # Pobierz umiejętności użytkownika
    skills = conn.execute('SELECT * FROM skills WHERE user_id = ?', (user['id'],)).fetchall()
    conn.close()
    
    return render_template('details.html', user=user, skills=skills, join_date=join_date)

@app.route('/account', methods=['GET', 'POST'])
def account():
    if request.method == 'POST':
        if 'username' in request.form:  # Rejestracja
            username = request.form['username']
            password = request.form['password']
            city = request.form['city']
            
            if len(username) < 3:
                flash('Username must be at least 3 characters long.', 'error')
                return redirect(url_for('account'))
            
            if len(password) < 6:
                flash('Password must be at least 6 characters long.', 'error')
                return redirect(url_for('account'))
            
            conn = get_db_connection()
            existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            
            if existing_user:
                flash('Username already exists. Please choose a different one.', 'error')
                return redirect(url_for('account'))
            
            hashed_password = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, password, city) VALUES (?, ?, ?)', (username, hashed_password, city))
            conn.commit()
            conn.close()
            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('account'))
        
        elif 'loginUsername' in request.form:  # Logowanie
            username = request.form['loginUsername']
            password = request.form['loginPassword']
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            conn.close()
            
            if user and check_password_hash(user['password'], password):
                session['username'] = username
                session['user_id'] = user['id'] 
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Login failed. Please check your username and password.', 'error')
                return redirect(url_for('account'))
    
    return render_template('account.html')
    
    return render_template('account.html')

@app.route('/new_offer', methods=['GET', 'POST'])
def new_offer():
    if request.method == 'POST':
        title = request.form['title']
        city = request.form['city']
        description = request.form['description']

        if not session.get('username'):
            flash('You need to log in to add an offer.', 'error')
            return redirect(url_for('account'))

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()

        conn.execute('INSERT INTO offers (title, city, description, user_id) VALUES (?, ?, ?, ?)',
                     (title, city, description, user['id']))
        conn.commit()
        conn.close()
        return redirect(url_for('new_offer'))
    
    return render_template('new_offer.html')

@app.route('/send_message/<int:receiver_id>', methods=['GET', 'POST'])
def send_message(receiver_id):
    if not session.get('username'):
        flash('Musisz się zalogować, aby wysłać wiadomość.', 'error')
        return redirect(url_for('account'))

    conn = get_db_connection()
    sender = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    receiver = conn.execute('SELECT * FROM users WHERE id = ?', (receiver_id,)).fetchone()

    if not receiver:
        flash('Odbiorca nie istnieje.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        message_text = request.form.get('message')
        if not message_text:
            flash('Wiadomość nie może być pusta.', 'error')
            return redirect(url_for('send_message', receiver_id=receiver_id))

        conn.execute('''
            INSERT INTO messages (sender_id, receiver_id, message)
            VALUES (?, ?, ?)
        ''', (sender['id'], receiver['id'], message_text))
        conn.commit()
        conn.close()

        flash('Wiadomość wysłana.', 'success')
        return redirect(url_for('view_conversation', receiver_id=receiver_id))

    conn.close()
    return render_template('send_message.html', receiver=receiver)


@app.route('/conversation/<int:receiver_id>')
def view_conversation(receiver_id):
    if not session.get('username'):
        flash('Musisz się zalogować, aby zobaczyć konwersację.', 'error')
        return redirect(url_for('account'))
    
    conn = get_db_connection()
    
    # Pobierz dane użytkowników
    sender = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    receiver = conn.execute('SELECT * FROM users WHERE id = ?', (receiver_id,)).fetchone()
    
    if not sender or not receiver:
        flash('Wystąpił błąd podczas pobierania konwersacji.', 'error')
        return redirect(url_for('index'))
    
    # Pobierz wiadomości między użytkownikami
    messages = conn.execute('''
        SELECT messages.*, 
               sender.username as sender_username, 
               receiver.username as receiver_username
        FROM messages
        JOIN users AS sender ON messages.sender_id = sender.id
        JOIN users AS receiver ON messages.receiver_id = receiver.id
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY messages.timestamp ASC
    ''', (sender['id'], receiver['id'], receiver['id'], sender['id'])).fetchall()
    
    conn.close()
    
    return render_template('conversation.html', messages=messages, receiver=receiver)

@app.route('/inbox')
def inbox():
    if not session.get('username'):
        flash('Musisz się zalogować, aby zobaczyć skrzynkę odbiorczą.', 'error')
        return redirect(url_for('account'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    
    if not user:
        flash('Użytkownik nie istnieje.', 'error')
        return redirect(url_for('index'))
    
    # Pobierz listę konwersacji z nazwami użytkowników
    conversations = conn.execute('''
        SELECT DISTINCT 
               CASE 
                   WHEN sender_id = ? THEN receiver.username
                   ELSE sender.username
               END AS other_user_name,
               CASE 
                   WHEN sender_id = ? THEN receiver.id
                   ELSE sender.id
               END AS other_user_id
        FROM messages
        JOIN users AS sender ON messages.sender_id = sender.id
        JOIN users AS receiver ON messages.receiver_id = receiver.id
        WHERE sender_id = ? OR receiver_id = ?
    ''', (user['id'], user['id'], user['id'], user['id'])).fetchall()
    
    conn.close()
    
    return render_template('inbox.html', conversations=conversations, user=user)

def generate_conversation_id(user1_id, user2_id):
    return f"{min(user1_id, user2_id)}:{max(user1_id, user2_id)}"

@app.route('/account_redirect')
def account_redirect():
    if session.get('username'):
        return redirect(url_for('account_details'))
    else:
        return redirect(url_for('account'))
    
@app.route('/manage_skills', methods=['GET', 'POST'])
def manage_skills():
    if not session.get('username'):
        flash('Musisz się zalogować, aby zarządzać umiejętnościami.', 'error')
        return redirect(url_for('account'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    
    if request.method == 'POST':
        skill_name = request.form['skill_name']
        if skill_name:
            conn.execute('INSERT INTO skills (user_id, skill_name) VALUES (?, ?)', (user['id'], skill_name))
            conn.commit()
            flash('Umiejętność została dodana.', 'success')
        else:
            flash('Nazwa umiejętności nie może być pusta.', 'error')
    
    # Pobierz umiejętności użytkownika
    skills = conn.execute('SELECT * FROM skills WHERE user_id = ?', (user['id'],)).fetchall()
    conn.close()
    
    return render_template('manage_skills.html', skills=skills)

@app.route('/propose_exchange/<int:receiver_id>', methods=['POST'])
def propose_exchange(receiver_id):
    if not session.get('username'):
        flash('Musisz się zalogować, aby proponować wymianę.', 'error')
        return redirect(url_for('account'))
    
    conn = get_db_connection()
    sender = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    receiver = conn.execute('SELECT * FROM users WHERE id = ?', (receiver_id,)).fetchone()
    
    if not sender or not receiver:
        flash('Wystąpił błąd podczas proponowania wymiany.', 'error')
        return redirect(url_for('index'))
    
    # Wyślij wiadomość z propozycją wymiany
    message_text = f"{sender['username']} proponuje ci wymianę umiejętności."
    conn.execute('''
        INSERT INTO messages (sender_id, receiver_id, message, exchange_status)
        VALUES (?, ?, ?, ?)
    ''', (sender['id'], receiver['id'], message_text, 'pending'))
    
    conn.commit()
    conn.close()
    
    flash('Propozycja wymiany została wysłana.', 'success')
    return redirect(url_for('view_conversation', receiver_id=receiver_id))

@app.route('/send_message/<int:receiver_id>', methods=['POST'])
@app.route('/send_message/<int:receiver_id>/<int:offer_id>', methods=['POST'])
def handle_send_message(receiver_id, offer_id=None):
    if not session.get('username'):
        flash('Musisz się zalogować, aby wysłać wiadomość.', 'error')
        return redirect(url_for('account'))
    
    message_text = request.form.get('message')
    
    if not message_text:
        flash('Wiadomość nie może być pusta.', 'error')
        return redirect(url_for('send_message', receiver_id=receiver_id, offer_id=offer_id))
    
    conn = get_db_connection()
    
    # Pobierz dane użytkowników
    sender = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    receiver = conn.execute('SELECT * FROM users WHERE id = ?', (receiver_id,)).fetchone()
    
    if not sender or not receiver:
        flash('Wystąpił błąd podczas wysyłania wiadomości.', 'error')
        return redirect(url_for('index'))
    
    # Wstaw wiadomość do bazy danych
    conn.execute('''
        INSERT INTO messages (sender_id, receiver_id, message, offer_id)
        VALUES (?, ?, ?, ?)
    ''', (sender['id'], receiver['id'], message_text, offer_id))
    
    conn.commit()
    conn.close()
    
    flash('Wiadomość została wysłana.', 'success')
    return redirect(url_for('view_conversation', receiver_id=receiver_id))

@app.route('/accept_proposal/<int:proposal_id>')
def accept_proposal(proposal_id):
    if not session.get('username'):
        flash('Musisz się zalogować, aby akceptować propozycje.', 'error')
        return redirect(url_for('account'))
    
    conn = get_db_connection()
    conn.execute('UPDATE exchange_proposals SET status = ? WHERE id = ?', ('accepted', proposal_id))
    conn.commit()
    conn.close()
    
    flash('Propozycja wymiany została zaakceptowana.', 'success')
    return redirect(url_for('conversation', receiver_id=...))  # Przekieruj do odpowiedniej konwersacji

@app.route('/reject_proposal/<int:proposal_id>')
def reject_proposal(proposal_id):
    if not session.get('username'):
        flash('Musisz się zalogować, aby odrzucać propozycje.', 'error')
        return redirect(url_for('account'))
    
    conn = get_db_connection()
    conn.execute('UPDATE exchange_proposals SET status = ? WHERE id = ?', ('rejected', proposal_id))
    conn.commit()
    conn.close()
    
    flash('Propozycja wymiany została odrzucona.', 'success')
    return redirect(url_for('conversation', receiver_id=...))  # Przekieruj do odpowiedniej konwersacji

@app.route('/add_skill', methods=['GET', 'POST'])
def add_skill():
    if not session.get('username'):
        flash('Musisz się zalogować, aby dodać umiejętność.', 'error')
        return redirect(url_for('account'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    
    if request.method == 'POST':
        skill_name = request.form['skill_name']
        description = request.form['description']
        
        if skill_name:
            conn.execute('INSERT INTO skills (user_id, skill_name, description) VALUES (?, ?, ?)', (user['id'], skill_name, description))
            conn.commit()
            flash('Umiejętność została dodana.', 'success')
        else:
            flash('Nazwa umiejętności nie może być pusta.', 'error')
    
    conn.close()
    return render_template('add_skill.html')

@app.route('/user/<int:user_id>')
def user_details(user_id):
    conn = get_db_connection()
    
    # Pobierz dane użytkownika
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        flash('Użytkownik nie istnieje.', 'error')
        return redirect(url_for('index'))
    
    # Przekształć join_date na obiekt datetime
    join_date = datetime.strptime(user['join_date'], '%Y-%m-%d %H:%M:%S')
    
    # Pobierz umiejętności użytkownika
    skills = conn.execute('SELECT * FROM skills WHERE user_id = ?', (user_id,)).fetchall()
    
    # Pobierz komentarze dla użytkownika wraz z nazwami autorów
    comments = conn.execute('''
        SELECT comments.*, users.username as author_username
        FROM comments
        JOIN users ON comments.author_id = users.id
        WHERE comments.user_id = ?
        ORDER BY comments.timestamp DESC
    ''', (user_id,)).fetchall()
    
    # Przekonwertuj każdy komentarz z sqlite3.Row na słownik i przekształć timestamp
    comments = [dict(comment) for comment in comments]
    for comment in comments:
        comment['timestamp'] = datetime.strptime(comment['timestamp'], '%Y-%m-%d %H:%M:%S')
    
    conn.close()
    
    return render_template('user_details.html', user=user, skills=skills, join_date=join_date, comments=comments)

@app.route('/accept_exchange/<int:message_id>', methods=['POST'])
def accept_exchange(message_id):
    if not session.get('username'):
        flash('Musisz się zalogować, aby akceptować wymianę.', 'error')
        return redirect(url_for('account'))
    
    conn = get_db_connection()
    
    # Pobierz wiadomość z propozycją wymiany
    message = conn.execute('SELECT * FROM messages WHERE id = ?', (message_id,)).fetchone()
    
    if not message:
        flash('Wiadomość nie istnieje.', 'error')
        return redirect(url_for('index'))
    
    # Sprawdź, czy użytkownik może zaakceptować tę wymianę
    if message['receiver_id'] != session.get('user_id'):
        flash('Nie możesz zaakceptować tej wymiany.', 'error')
        return redirect(url_for('index'))
    
    # Zaktualizuj status wymiany na 'accepted'
    conn.execute('UPDATE messages SET exchange_status = ? WHERE id = ?', ('accepted', message_id))
    conn.commit()
    conn.close()
    
    flash('Wymiana została zaakceptowana.', 'success')
    return redirect(url_for('view_conversation', receiver_id=message['sender_id']))

@app.route('/reject_exchange/<int:message_id>', methods=['POST'])
def reject_exchange(message_id):
    if not session.get('username'):
        flash('Musisz się zalogować, aby odrzucać wymianę.', 'error')
        return redirect(url_for('account'))
    
    conn = get_db_connection()
    
    # Pobierz wiadomość z propozycją wymiany
    message = conn.execute('SELECT * FROM messages WHERE id = ?', (message_id,)).fetchone()
    
    if not message:
        flash('Wiadomość nie istnieje.', 'error')
        return redirect(url_for('index'))
    
    # Sprawdź, czy użytkownik może odrzucić tę wymianę
    if message['receiver_id'] != session.get('user_id'):
        flash('Nie możesz odrzucić tej wymiany.', 'error')
        return redirect(url_for('index'))
    
    # Zaktualizuj status wymiany na 'rejected'
    conn.execute('UPDATE messages SET exchange_status = ? WHERE id = ?', ('rejected', message_id))
    conn.commit()
    conn.close()
    
    flash('Wymiana została odrzucona.', 'success')
    return redirect(url_for('view_conversation', receiver_id=message['sender_id']))

@app.route('/complete_exchange/<int:receiver_id>', methods=['POST'])
def complete_exchange(receiver_id):
    if not session.get('username'):
        flash('Musisz się zalogować, aby zakończyć wymianę.', 'error')
        return redirect(url_for('account'))
    
    conn = get_db_connection()
    sender = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    receiver = conn.execute('SELECT * FROM users WHERE id = ?', (receiver_id,)).fetchone()
    
    if not sender or not receiver:
        flash('Wystąpił błąd podczas zakończenia wymiany.', 'error')
        return redirect(url_for('index'))
    
    # Wyślij wiadomość o zakończeniu wymiany
    message_text = f"{sender['username']} zakończył wymianę pomyślnie."
    conn.execute('''
        INSERT INTO messages (sender_id, receiver_id, message, exchange_status)
        VALUES (?, ?, ?, ?)
    ''', (sender['id'], receiver['id'], message_text, 'completed'))
    
    conn.commit()
    conn.close()
    
    flash('Wymiana została zakończona.', 'success')
    return redirect(url_for('view_conversation', receiver_id=receiver_id))

@app.route('/change_password', methods=['POST'])
def change_password():
    if not session.get('username'):
        flash('Musisz się zalogować, aby zmienić hasło.', 'error')
        return redirect(url_for('account'))
    
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    
    if not current_password or not new_password:
        flash('Wypełnij wszystkie pola.', 'error')
        return redirect(url_for('account_details'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    
    if not user:
        flash('Użytkownik nie istnieje.', 'error')
        return redirect(url_for('index'))
    
    # Sprawdź, czy obecne hasło jest poprawne
    if not check_password_hash(user['password'], current_password):
        flash('Obecne hasło jest nieprawidłowe.', 'error')
        return redirect(url_for('account_details'))
    
    # Sprawdź, czy nowe hasło ma co najmniej 6 znaków
    if len(new_password) < 6:
        flash('Nowe hasło musi mieć co najmniej 6 znaków.', 'error')
        return redirect(url_for('account_details'))
    
    # Zaktualizuj hasło w bazie danych
    hashed_password = generate_password_hash(new_password)
    conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user['id']))
    conn.commit()
    conn.close()
    
    flash('Hasło zostało zmienione pomyślnie.', 'success')
    return redirect(url_for('account_details'))

@app.route('/add_comment/<int:user_id>', methods=['POST'])
def add_comment(user_id):
    if not session.get('username'):
        flash('Musisz się zalogować, aby dodać komentarz.', 'error')
        return redirect(url_for('account'))
    
    # Sprawdź, czy użytkownik nie próbuje dodać komentarza do swojego własnego profilu
    if session.get('user_id') == user_id:
        flash('Nie możesz dodać komentarza do swojego własnego profilu.', 'error')
        return redirect(url_for('user_details', user_id=user_id))
    
    comment_text = request.form['comment']
    
    if not comment_text:
        flash('Komentarz nie może być pusty.', 'error')
        return redirect(url_for('user_details', user_id=user_id))
    
    conn = get_db_connection()
    
    # Dodaj komentarz do bazy danych
    conn.execute('''
        INSERT INTO comments (user_id, author_id, comment)
        VALUES (?, ?, ?)
    ''', (user_id, session['user_id'], comment_text))
    
    conn.commit()
    conn.close()
    
    flash('Komentarz został dodany.', 'success')
    return redirect(url_for('user_details', user_id=user_id))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
