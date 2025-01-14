# Create a new file called models.py
from typing import Dict, List, Optional
import shelve
import bcrypt

class User:
    def __init__(self, username: str, password: str, phone: str, role: str):
        self.__username = username
        self.__password = password  # Should be already hashed when creating from DB
        self.__phone = phone
        self.__role = role
    
    # Getters
    @property
    def username(self) -> str:
        return self.__username
    
    @property
    def password(self) -> bytes:
        return self.__password
    
    @property
    def phone(self) -> str:
        return self.__phone
    
    @property
    def role(self) -> str:
        return self.__role
    
    # Setters with validation
    @phone.setter
    def phone(self, new_phone: str) -> None:
        if not new_phone.strip():
            raise ValueError("Phone number cannot be empty")
        self.__phone = new_phone
    
    def verify_password(self, password: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), self.__password)
    
    def to_dict(self) -> Dict:
        return {
            'username': self.__username,
            'password': self.__password,
            'phone': self.__phone,
            'role': self.__role
        }

class UserManager:
    def __init__(self):
        self.__db_name = 'users_db'
    
    def __get_db(self):
        return shelve.open(self.__db_name)
    
    def create_user(self, username: str, password: str, phone: str, role: str) -> bool:
        """Create a new user"""
        with self.__get_db() as db:
            if username in db:
                return False
            
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user = User(username, hashed_password, phone, role)
            db[username] = user.to_dict()
            return True
    
    def get_user(self, username: str) -> Optional[User]:
        """Get user by username"""
        with self.__get_db() as db:
            if username not in db:
                return None
            data = db[username]
            return User(
                data['username'],
                data['password'],
                data['phone'],
                data['role']
            )
    
    def update_user(self, username: str, phone: str) -> bool:
        """Update user details"""
        with self.__get_db() as db:
            if username not in db:
                return False
            user_data = db[username]
            user = User(
                user_data['username'],
                user_data['password'],
                phone,  # Update phone
                user_data['role']
            )
            db[username] = user.to_dict()
            return True
    
    def delete_user(self, username: str) -> bool:
        """Delete a user"""
        with self.__get_db() as db:
            if username not in db:
                return False
            del db[username]
            return True
    
    def get_all_users(self) -> List[User]:
        """Get all users"""
        with self.__get_db() as db:
            return [User(
                data['username'],
                data['password'],
                data['phone'],
                data['role']
            ) for data in db.values()]
    
    def get_users_by_role(self, role: str) -> List[User]:
        """Get users filtered by role"""
        with self.__get_db() as db:
            return [User(
                data['username'],
                data['password'],
                data['phone'],
                data['role']
            ) for data in db.values() if data['role'] == role]
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user login"""
        user = self.get_user(username)
        if user and user.verify_password(password):
            return user
        return None