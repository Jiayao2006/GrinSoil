# models.py
from typing import Dict, List, Optional
import shelve
import bcrypt
from datetime import datetime, timedelta

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

class Product:
    def __init__(self, id: str, name: str, expiry_date: str, status: str, owner: str):
        self.__id = id
        self.__name = name
        self.__expiry_date = expiry_date
        self.__status = status
        self.__owner = owner
    
    @property
    def id(self) -> str:
        return self.__id
    
    @property
    def name(self) -> str:
        return self.__name
    
    @property
    def expiry_date(self) -> str:
        return self.__expiry_date
    
    @property
    def status(self) -> str:
        if self.__status == 'eaten':
            return self.__status
            
        # Calculate current status based on expiry date
        expiry = datetime.strptime(self.__expiry_date, '%Y-%m-%d')
        today = datetime.now()
        days_until_expiry = (expiry - today).days
        
        if days_until_expiry < 0:
            return 'expired'
        elif days_until_expiry <= 3:
            return 'expiring-soon'
        else:
            return 'fresh'
    
    @status.setter
    def status(self, new_status: str) -> None:
        if new_status not in ['fresh', 'expiring-soon', 'expired', 'eaten']:
            raise ValueError("Invalid status")
        self.__status = new_status
    
    @property
    def owner(self) -> str:
        return self.__owner
    
    def to_dict(self) -> Dict:
        return {
            'id': self.__id,
            'name': self.__name,
            'expiry_date': self.__expiry_date,
            'status': self.__status,
            'owner': self.__owner
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
        """Delete a user and their products"""
        with self.__get_db() as db:
            if username not in db:
                return False
            # Delete user's products first
            product_manager = ProductManager()
            product_manager.delete_user_products(username)
            # Then delete the user
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

class ProductManager:
    def __init__(self):
        self.__db_name = 'products_db'
    
    def __get_db(self):
        return shelve.open(self.__db_name)
    
    def create_product(self, name: str, expiry_date: str, owner: str) -> str:
        """Create a new product"""
        with self.__get_db() as db:
            product_id = str(datetime.now().timestamp())
            # Initialize with calculated status
            product = Product(product_id, name, expiry_date, 'fresh', owner)
            db[product_id] = product.to_dict()
            return product_id
    
    def get_user_products(self, username: str) -> List[Product]:
        """Get all products for a specific user"""
        with self.__get_db() as db:
            return [Product(
                data['id'],
                data['name'],
                data['expiry_date'],
                data['status'],
                data['owner']
            ) for data in db.values() if data['owner'] == username]
    
    def update_product_status(self, product_id: str, new_status: str) -> bool:
        """Update product status"""
        with self.__get_db() as db:
            if product_id not in db:
                return False
            product_data = db[product_id]
            product = Product(
                product_data['id'],
                product_data['name'],
                product_data['expiry_date'],
                new_status,
                product_data['owner']
            )
            db[product_id] = product.to_dict()
            return True
    
    def delete_product(self, product_id: str) -> bool:
        """Delete a product"""
        with self.__get_db() as db:
            if product_id not in db:
                return False
            del db[product_id]
            return True
    
    def delete_user_products(self, username: str) -> None:
        """Delete all products for a specific user"""
        with self.__get_db() as db:
            # Get all product IDs for the user
            product_ids = [id for id, data in db.items() if data['owner'] == username]
            # Delete each product
            for product_id in product_ids:
                del db[product_id]
    
    def get_status_counts(self, username: str) -> Dict[str, int]:
        """Get counts of fresh and expiring soon products for a user"""
        products = self.get_user_products(username)
        counts = {
            'fresh': 0,
            'expiring-soon': 0
        }
        for product in products:
            if product.status in counts:
                counts[product.status] += 1
        return counts