import sqlite3
import hashlib
import os
import re

mail = "test@gmail.com"
password = "Password&123"


def generate_salt(length=16):
    """Génère un sel aléatoire."""
    return os.urandom(length)


def hash_password(password: str, salt=None):
    """Hache un mot de passe avec un sel."""
    if salt is None:
        salt = generate_salt()
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return hashed_password, salt


def is_password_correct(hashed_password: str, salt: str, provided_password: str) -> bool:
    """Vérifie si un mot de passe fourni correspond au haché."""
    new_hashed_password, _ = hash_password(provided_password, salt)
    return hashed_password == new_hashed_password


def is_mail_in_bdd(mail: str) -> bool:
    """Vérifie si un email se trouve dans la base de données."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Requête pour rechercher l'email dans la base de données
    cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (mail,))
    count = cursor.fetchone()[0]

    conn.close()

    # Si count est supérieur à 0, cela signifie que l'email est présent dans la base de données
    return count > 0


def is_password_strong(password: str) -> [bool, str]:
    """Vérifie la force d'un mot de passe."""
    # Vérifie si le mot de passe a au moins 8 caractères
    if len(password) < 8:
        return False, "Le mot de passe doit contenir au moins 8 caractères."

    # Vérifie s'il y a au moins une lettre majuscule
    if not any(char.isupper() for char in password):
        return False, "Le mot de passe doit contenir au moins une lettre majuscule."

    # Vérifie s'il y a au moins un caractère spécial
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Le mot de passe doit contenir au moins un caractère spécial."

    # Si toutes les conditions sont satisfaites, le mot de passe est considéré comme fort
    return True, "Le mot de passe est fort."


def add_user(mail: str, password: str) -> bool:
    if not is_mail_in_bdd(mail):
        """Ajoute un utilisateur à la base de données."""
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Générer le sel et hacher le mot de passe
        hashed_password, salt = hash_password(password)

        # Insérer l'utilisateur dans la base de données
        cursor.execute('''INSERT INTO users (email, hashed_password, salt)
                              VALUES (?, ?, ?)''', (mail, hashed_password, salt))

        conn.commit()
        conn.close()

        return True
    else:
        return False


def change_password(mail: str, new_password: str) -> bool:
    """Change le mot de passe d'un utilisateur dans la base de données."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Générer le sel et hacher le nouveau mot de passe
    hashed_password, salt = hash_password(new_password)

    # Mettre à jour le mot de passe dans la base de données
    cursor.execute('''UPDATE users SET hashed_password = ?, salt = ? WHERE email = ?''',
                   (hashed_password, salt, mail))

    conn.commit()
    conn.close()

    return True

def create_database():
    """Crée la base de données et la table."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Création de la table pour stocker les utilisateurs
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        email TEXT UNIQUE,
                        hashed_password BLOB,
                        salt BLOB
                    )''')

    conn.commit()
    conn.close()