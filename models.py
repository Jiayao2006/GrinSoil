# models.py
from typing import Dict, List, Optional
import shelve
import bcrypt
from datetime import datetime, timedelta
from dataclasses import dataclass
import os
from werkzeug.utils import secure_filename
import jwt
import uuid
import json
import traceback
import random


class User:
    def __init__(self, username: str, password: str, phone: str, role: str, email: str = None):
        self.__username = username
        self.__password = password  # Should be already hashed when creating from DB
        self.__phone = phone
        self.__role = role
        self.__email = email

    
    # Getters
    @property
    def username(self) -> str:
        return self.__username
    
     # Add email property
    @property
    def email(self) -> str:
        return self.__email
    
    @property
    def password(self) -> bytes:
        return self.__password
    
    @property
    def phone(self) -> str:
        return self.__phone
    
    @property
    def role(self) -> str:
        return self.__role
    
    # Add email property
    # @property
    # def email(self) -> str:
    #     return self.__email
    
    def to_dict(self) -> Dict:
        return {
            'username': self.__username,
            'password': self.__password,
            'phone': self.__phone,
            'role': self.__role,
            'email': self.__email
        }

    
    # Setters with validation
    @phone.setter
    def phone(self, new_phone: str) -> None:
        if not new_phone.strip():
            raise ValueError("Phone number cannot be empty")
        self.__phone = new_phone
    
    def verify_password(self, password: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), self.__password)
    
    # def to_dict(self) -> Dict:
    #     return {
    #         'username': self.__username,
    #         'password': self.__password,
    #         'phone': self.__phone,
    #         'role': self.__role
    #     }

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
        return shelve.open(self.__db_name, writeback=True)
    
    def create_user(self, username: str, password: str, phone: str, role: str, email: str = None) -> bool:
        """Create a new user"""
        try:
            with self.__get_db() as db:
                # If username exists, first delete the old user data completely
                if username in db:
                    self.delete_user(username)
                
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                user = User(username, hashed_password, phone, role, email)
                db[username] = user.to_dict()
                return True
                
        except Exception as e:
            print(f"Error in create_user: {str(e)}")
            return False
    
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
        
    # In NotificationManager class
    # def delete_farmer_notifications(self, farmer_username: str):
    #     """Delete notifications related to the farmer"""
    #     try:
    #         print(f"Attempting to delete notifications for farmer: {farmer_username}")
    #         with self.__get_db() as db:
    #             # Get all notification IDs to delete
    #             notifications_to_delete = []
                
    #             # Find all notifications that are either:
    #             # 1. Targeted to this farmer specifically
    #             # 2. Generated by/about this farmer's actions
    #             for key, notification_data in list(db.items()):  # Use list to avoid runtime modification
    #                 if (notification_data.get('target_role') == 'Farmer' and 
    #                     (notification_data.get('target_user') == farmer_username or
    #                     notification_data.get('content', '').lower().find(farmer_username.lower()) != -1)):
    #                     notifications_to_delete.append(key)
                
    #             # Delete the collected notifications
    #             deleted_count = 0
    #             for key in notifications_to_delete:
    #                 try:
    #                     del db[key]
    #                     deleted_count += 1
    #                 except Exception as e:
    #                     print(f"Error deleting notification {key}: {str(e)}")
                        
    #             print(f"Successfully deleted {deleted_count} notifications for farmer {farmer_username}")
    #             db.sync()  # Ensure changes are written to disk
                
    #     except Exception as e:
    #         print(f"Error deleting farmer notifications: {str(e)}")
    #         import traceback
    #         traceback.print_exc()
    
    def delete_user(self, username: str) -> bool:
        """Delete a user and all associated data"""
        try:
            # First, get the user data
            user_data = None
            with self.__get_db() as db:
                if username not in db:
                    print(f"User {username} not found in database")
                    return False
                user_data = db[username].copy()  # Make a copy of the data
            
            if not user_data:
                return False

            try:
                # If it's a farmer, delete all associated data first
                if user_data['role'] == 'Farmer':
                    # Delete listed products first
                    listed_product_manager = ListedProductManager()
                    listed_product_manager.delete_farmer_products(username)
                    
                    # Delete related orders
                    order_manager = OrderManager()
                    order_manager.delete_farmer_orders(username)
                    
                    # Delete farmer-specific notifications
                    try:
                        with shelve.open('notifications_db', 'w') as notifications_db:
                            # Get all notifications to delete
                            keys_to_delete = []
                            for key in notifications_db.keys():
                                notification_data = notifications_db[key]
                                # Delete notifications targeted to this farmer
                                if (notification_data.get('target_role') == 'Farmer' and 
                                    (notification_data.get('target_user') == username or
                                    notification_data.get('content', '').lower().find(username.lower()) != -1)):
                                    keys_to_delete.append(key)
                            
                            # Delete the collected notifications
                            for key in keys_to_delete:
                                del notifications_db[key]
                    except Exception as e:
                        print(f"Error deleting farmer notifications: {str(e)}")
            except Exception as e:
                print(f"Error deleting farmer-specific data: {str(e)}")

            # Delete standard user data
            try:
                product_manager = ProductManager()
                product_manager.delete_user_products(username)
            except Exception as e:
                print(f"Error deleting user products: {str(e)}")
            
            try:
                cart_manager = CartManager()
                cart_manager.clear_cart(username)
            except Exception as e:
                print(f"Error clearing cart: {str(e)}")
            
            # Clear notification read status
            try:
                with shelve.open('notifications_db', 'w') as notifications_db:
                    for key in list(notifications_db.keys()):  # Create a list to avoid runtime modification issues
                        notification_data = notifications_db[key]
                        if 'read_by' in notification_data and username in notification_data['read_by']:
                            notification_data['read_by'].remove(username)
                            notifications_db[key] = notification_data
            except Exception as e:
                print(f"Error clearing notification read status: {str(e)}")

            # Finally delete the user
            try:
                with self.__get_db() as db:
                    if username in db:
                        del db[username]
                        print(f"Successfully deleted user {username}")
                        return True
                    return False
            except Exception as e:
                print(f"Error deleting user from database: {str(e)}")
                return False

        except Exception as e:
            print(f"Error in delete_user: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    
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
            print(f"Authenticated user: {user.username}, role: {user.role}")  # Debug print
            return user
        return None
    
    def delete_user_data(self, username: str, role: str) -> bool:
        """Delete all data associated with a user"""
        try:
            print(f"Starting deletion of data for user {username} with role {role}")
            
            # Delete orders
            try:
                with shelve.open('orders_db', 'w') as orders_db:
                    if 'orders' in orders_db:
                        # Get all orders
                        orders = orders_db['orders']
                        original_count = len(orders)
                        
                        # Filter out user's orders
                        orders = {k: v for k, v in orders.items() 
                                if v.get('username') != username}
                        new_count = len(orders)
                        
                        print(f"Removed {original_count - new_count} orders for user {username}")
                        orders_db['orders'] = orders
            except Exception as e:
                print(f"Error deleting orders: {str(e)}")

            # Delete reviews
            try:
                review_manager = ReviewManager()
                user_reviews = review_manager.get_user_reviews(username)
                print(f"Found {len(user_reviews)} reviews to delete")
                for review in user_reviews:
                    review_manager.delete_review(review.id)
            except Exception as e:
                print(f"Error deleting reviews: {str(e)}")

            # Delete notifications
            try:
                with shelve.open('notifications_db', 'w') as notifications_db:
                    for key in list(notifications_db.keys()):
                        try:
                            notification = notifications_db[key]
                            # Remove notifications where user is mentioned
                            if (username in str(notification.get('content', '')) or
                                notification.get('target_user') == username):
                                del notifications_db[key]
                            else:
                                # Remove user from read_by lists
                                read_by = notification.get('read_by', [])
                                if username in read_by:
                                    read_by.remove(username)
                                    notification['read_by'] = read_by
                                    notifications_db[key] = notification
                        except Exception as e:
                            print(f"Error processing notification {key}: {str(e)}")
                            continue
            except Exception as e:
                print(f"Error deleting notifications: {str(e)}")

            # Delete products and expiry tracker items
            try:
                product_manager = ProductManager()
                product_manager.delete_user_products(username)
            except Exception as e:
                print(f"Error deleting products: {str(e)}")

            # Delete cart
            try:
                cart_manager = CartManager()
                cart_manager.clear_cart(username)
            except Exception as e:
                print(f"Error clearing cart: {str(e)}")

            # If user is a farmer, handle farmer-specific data
            if role == 'Farmer':
                try:
                    # Delete listed products
                    listed_product_manager = ListedProductManager()
                    listed_product_manager.delete_farmer_products(username)

                    # Update orders that reference this farmer
                    with shelve.open('orders_db', 'w') as orders_db:
                        if 'orders' in orders_db:
                            orders = orders_db['orders']
                            for order_id, order_data in orders.items():
                                farmer_statuses = order_data.get('farmer_statuses', {})
                                if username in farmer_statuses:
                                    # Remove farmer status
                                    del farmer_statuses[username]
                                    order_data['farmer_statuses'] = farmer_statuses
                                    
                                    # Remove items from this farmer
                                    items = order_data.get('items', [])
                                    items = [item for item in items 
                                           if item.get('farmer_username') != username]
                                    order_data['items'] = items
                                    
                                    orders[order_id] = order_data
                            orders_db['orders'] = orders
                except Exception as e:
                    print(f"Error handling farmer-specific data: {str(e)}")

            print(f"Successfully completed data deletion for user {username}")
            return True
            
        except Exception as e:
            print(f"Error deleting user data: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

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
    
    def get_product(self, product_id: str) -> Optional[Product]:
        """Get a specific product"""
        with self.__get_db() as db:
            if product_id not in db:
                return None
            data = db[product_id]
            return Product(
                data['id'],
                data['name'],
                data['expiry_date'],
                data['status'],
                data['owner']
            )

    def update_product(self, product_id: str, name: str, expiry_date: str) -> bool:
        """Update product details"""
        with self.__get_db() as db:
            if product_id not in db:
                return False
            product_data = db[product_id]
            # Keep existing status and owner
            product = Product(
                product_id,
                name,
                expiry_date,
                product_data['status'],
                product_data['owner']
            )
            db[product_id] = product.to_dict()
            return True
        
"""Review section"""
class Review:
    def __init__(self, id: str, content: str, author: str, created_at: str, updated_at: str = None):
        self.__id = id
        self.__content = content
        self.__author = author
        self.__created_at = created_at
        self.__updated_at = updated_at

    @property
    def id(self) -> str:
        return self.__id
    
    @property
    def content(self) -> str:
        return self.__content
    
    @property
    def author(self) -> str:
        return self.__author
    
    @property
    def created_at(self) -> str:
        return self.__created_at
    
    @property
    def updated_at(self) -> str:
        return self.__updated_at
    
    @content.setter
    def content(self, new_content: str) -> None:
        if not new_content.strip():
            raise ValueError("Review content cannot be empty")
        self.__content = new_content
        self.__updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def to_dict(self) -> Dict:
        return {
            'id': self.__id,
            'content': self.__content,
            'author': self.__author,
            'created_at': self.__created_at,
            'updated_at': self.__updated_at
        }

class ReviewManager:
    def __init__(self):
        self.__db_name = 'reviews_db'
    
    def __get_db(self):
        return shelve.open(self.__db_name)
    
    def create_review(self, content: str, author: str) -> str:
        """Create a new review"""
        with self.__get_db() as db:
            review_id = str(datetime.now().timestamp())
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            review = Review(review_id, content, author, created_at)
            db[review_id] = review.to_dict()
            return review_id
    
    def get_all_reviews(self) -> List[Review]:
        """Get all reviews"""
        with self.__get_db() as db:
            return [Review(
                data['id'],
                data['content'],
                data['author'],
                data['created_at'],
                data['updated_at']
            ) for data in db.values()]
    
    def get_user_reviews(self, username: str) -> List[Review]:
        """Get all reviews by a specific user"""
        with self.__get_db() as db:
            return [Review(
                data['id'],
                data['content'],
                data['author'],
                data['created_at'],
                data['updated_at']
            ) for data in db.values() if data['author'] == username]
    
    def update_review(self, review_id: str, content: str) -> bool:
        """Update a review"""
        with self.__get_db() as db:
            if review_id not in db:
                return False
            review_data = db[review_id]
            review = Review(
                review_id,
                content,
                review_data['author'],
                review_data['created_at'],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            db[review_id] = review.to_dict()
            return True
    
    def delete_review(self, review_id: str) -> bool:
        """Delete a review"""
        with self.__get_db() as db:
            if review_id not in db:
                return False
            del db[review_id]
            return True
    
    def get_review(self, review_id: str) -> Optional[Review]:
        """Get a specific review"""
        with self.__get_db() as db:
            if review_id not in db:
                return None
            data = db[review_id]
            return Review(
                data['id'],
                data['content'],
                data['author'],
                data['created_at'],
                data['updated_at']
            )
        
    def get_user_review_count(self, username: str) -> int:
        """Get the count of reviews for a specific user"""
        try:
            reviews = self.get_user_reviews(username)
            return len(reviews)
        except Exception as e:
            print(f"Error getting review count: {str(e)}")
            return 0
        
class Notification:
    def __init__(self, id: str, title: str, content: str, target_role: str, created_at: str, read_by: List[str] = None, updated_at: str = None, target_user: str = None):
        self.__id = id
        self.__title = title
        self.__content = content
        self.__target_role = target_role
        self.__created_at = created_at
        self.__updated_at = updated_at
        self.__read_by = read_by if read_by is not None else []
        self.__target_user = target_user  # Add this line

    @property
    def target_user(self) -> str:
        return self.__target_user

    @property
    def id(self) -> str:
        return self.__id
    
    @property
    def title(self) -> str:
        return self.__title
    
    @property
    def content(self) -> str:
        return self.__content
    
    @property
    def target_role(self) -> str:
        return self.__target_role
    
    @property
    def created_at(self) -> str:
        return self.__created_at
    
    @property
    def updated_at(self) -> str:
        return self.__updated_at
    
    @property
    def read_by(self) -> List[str]:
        return self.__read_by

    def mark_as_read(self, username: str) -> None:
        if username not in self.__read_by:
            self.__read_by.append(username)

    def mark_as_unread(self, username: str) -> None:
        if username in self.__read_by:
            self.__read_by.remove(username)

    def is_read_by(self, username: str) -> bool:
        return username in (self.__read_by or [])

    def to_dict(self) -> Dict:
        return {
            'id': self.__id,
            'title': self.__title,
            'content': self.__content,
            'target_role': self.__target_role,
            'created_at': self.__created_at,
            'updated_at': self.__updated_at,
            'read_by': self.__read_by,
            'target_user': self.__target_user,  # Add this line
        }


class NotificationManager:
    def __init__(self):
        self.__db_name = 'notifications_db'
        self.__init_db()

    def __init_db(self):
        """Initialize database with error checking"""
        try:
            with shelve.open(self.__db_name, 'c') as db:
                # Test write
                test_key = '__test__'
                test_data = {
                    'id': test_key,
                    'title': 'Test Notification',
                    'content': 'Test Content',
                    'target_role': 'All',
                    'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'read_by': [],
                    'updated_at': None
                }
                db[test_key] = test_data
                
                # Verify write
                verification = db[test_key]
                if verification != test_data:
                    raise Exception("Database verification failed")
                
                # Clean up test entry
                del db[test_key]
                
        except Exception as e:
            print(f"Error initializing notification database: {str(e)}")
            raise
    
    def __get_db(self):
        return shelve.open(self.__db_name, writeback=True)
    
    def create_notification(self, title: str, content: str, target_role: str, target_user: str = None) -> str:
        """Create a new notification with improved error handling and verification"""
        try:
            with self.__get_db() as db:
                notification_id = str(datetime.now().timestamp())
                notification_data = {
                    'id': notification_id,
                    'title': title,
                    'content': content,
                    'target_role': target_role,
                    'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'read_by': [],
                    'updated_at': None,
                    'target_user': target_user,  # Add this line
                }
                
                # Write notification
                db[notification_id] = notification_data
                db.sync()
                
                # Verify write
                verification = db.get(notification_id)
                if not verification or verification != notification_data:
                    raise Exception("Notification verification failed")
                
                return notification_id
                
        except Exception as e:
            print(f"Error creating notification: {str(e)}")
            return None

    
    def get_all_notifications(self) -> List[Notification]:
        """Get all notifications"""
        try:
            print("Fetching all notifications")
            with self.__get_db() as db:
                notifications = []
                print(f"Database keys: {list(db.keys())}")  # Debug print
                
                for key, data in db.items():
                    try:
                        if key != '__test__':  # Skip test entry
                            print(f"Processing notification data: {data}")  # Debug print
                            notification = Notification(
                                id=data['id'],
                                title=data['title'],
                                content=data['content'],
                                target_role=data['target_role'],
                                created_at=data['created_at'],
                                read_by=data.get('read_by', []),
                                updated_at=data.get('updated_at')
                            )
                            notifications.append(notification)
                    except Exception as e:
                        print(f"Error processing notification {key}: {str(e)}")
                        continue
                        
                print(f"Found {len(notifications)} notifications")
                return notifications
        except Exception as e:
            print(f"Error getting all notifications: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_notifications_for_role(self, role: str, username: str = None) -> List[Notification]:
        """Get notifications for a specific role and user with improved filtering"""
        try:
            with self.__get_db() as db:
                notifications = []
                for key in list(db.keys()):
                    if key == '__test__':
                        continue
                        
                    try:
                        data = db[key]
                        # Check if notification is for the correct role
                        if data.get('target_role') not in [role, 'All']:
                            continue
                            
                        # Check target user
                        target_user = data.get('target_user')
                        if target_user and target_user != username:
                            continue
                            
                        notification = Notification(
                            id=data['id'],
                            title=data['title'],
                            content=data['content'],
                            target_role=data['target_role'],
                            created_at=data['created_at'],
                            read_by=data.get('read_by', []),
                            updated_at=data.get('updated_at'),
                            target_user=target_user
                        )
                        notifications.append(notification)
                    except Exception as e:
                        print(f"Error processing notification {key}: {str(e)}")
                        continue
                        
                # Sort by created date, most recent first
                notifications.sort(
                    key=lambda x: datetime.strptime(x.created_at, "%Y-%m-%d %H:%M:%S"),
                    reverse=True
                )
                return notifications
        except Exception as e:
            print(f"Error in get_notifications_for_role: {str(e)}")
            return []

    
    def mark_notification_as_read(self, notification_id: str, username: str) -> bool:
        """Mark a notification as read for a specific user"""
        try:
            with self.__get_db() as db:
                if notification_id not in db:
                    return False
                
                notification_data = db[notification_id]
                read_by = notification_data.get('read_by', [])
                
                if username not in read_by:
                    read_by.append(username)
                    notification_data['read_by'] = read_by
                    db[notification_id] = notification_data
                    db.sync()  # Force write to disk
                return True
        except Exception as e:
            print(f"Error marking notification as read: {str(e)}")
            return False
    
    def mark_notification_as_unread(self, notification_id: str, username: str) -> bool:
        """Mark a notification as unread for a specific user"""
        try:
            with self.__get_db() as db:
                if notification_id not in db:
                    return False
                
                notification_data = db[notification_id]
                read_by = notification_data.get('read_by', [])
                
                if username in read_by:
                    read_by.remove(username)
                    notification_data['read_by'] = read_by
                    db[notification_id] = notification_data
                    db.sync()  # Force write to disk
                return True
        except Exception as e:
            print(f"Error marking notification as unread: {str(e)}")
            return False
    
    def get_recent_notifications(self, role: str, username: str, limit: int = 5) -> List[Notification]:
        """Get recent notifications with proper filtering and limiting"""
        try:
            # Get all notifications for role and user
            notifications = self.get_notifications_for_role(role, username)
            
            # Filter to most recent
            recent = notifications[:limit]
            
            return recent
        except Exception as e:
            print(f"Error getting recent notifications: {str(e)}")
            return []

    def get_notification_counts(self, role: str, username: str) -> Dict[str, int]:
        """Get accurate notification counts for a user"""
        try:
            notifications = self.get_notifications_for_role(role, username)
            
            # Count total and unread
            total = len(notifications)
            unread = len([n for n in notifications 
                        if username not in n.read_by])
            
            return {
                'total': total,
                'unread': unread
            }
        except Exception as e:
            print(f"Error getting notification counts: {str(e)}")
            return {'total': 0, 'unread': 0}
    
    def update_notification(self, notification_id: str, title: str, content: str, target_role: str) -> bool:
        """Update an existing notification"""
        try:
            with self.__get_db() as db:
                if notification_id not in db:
                    return False
                
                notification_data = db[notification_id]
                notification_data.update({
                    'title': title,
                    'content': content,
                    'target_role': target_role,
                    'updated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                db[notification_id] = notification_data
                db.sync()  # Force write to disk
                return True
        except Exception as e:
            print(f"Error updating notification: {str(e)}")
            return False
    
    def delete_notification(self, notification_id: str) -> bool:
        """Delete a notification"""
        try:
            with self.__get_db() as db:
                if notification_id not in db:
                    return False
                del db[notification_id]
                db.sync()  # Force write to disk
                return True
        except Exception as e:
            print(f"Error deleting notification: {str(e)}")
            return False
    
    def get_notification(self, notification_id: str) -> Optional[Notification]:
        """Get a specific notification"""
        try:
            with self.__get_db() as db:
                if notification_id not in db:
                    return None
                data = db[notification_id]
                return Notification(
                    data['id'],
                    data['title'],
                    data['content'],
                    data['target_role'],
                    data['created_at'],
                    data.get('read_by', []),
                    data.get('updated_at')
                )
        except Exception as e:
            print(f"Error getting notification: {str(e)}")
            return None
        
class ListedProduct(Product):
    def __init__(self, id: str, name: str, expiry_date: str, owner: str,
                 category: str, price: float, quantity: int, unit: str, 
                 harvest_date: str, description: str, additional_info: str = None, 
                 images: List[str] = None, listing_status: str = "active"):
        # Call parent class constructor
        super().__init__(id, name, expiry_date, 'fresh', owner)
        
        # Add additional attributes specific to listed products
        self.__category = category
        self.__price = price
        self.__quantity = quantity
        self.__unit = unit
        self.__harvest_date = harvest_date
        self.__description = description
        self.__additional_info = additional_info
        self.__images = images if images else []
        self.__listing_status = listing_status  # active, sold_out, removed
        self.__created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.__updated_at = None

    # Additional getters for new attributes
    @property
    def category(self) -> str:
        return self.__category
    
    @property
    def price(self) -> float:
        return self.__price
    
    @property
    def quantity(self) -> int:
        return self.__quantity
    
    @property
    def unit(self) -> str:
        return self.__unit
    
    @property
    def harvest_date(self) -> str:
        return self.__harvest_date
    
    @property
    def description(self) -> str:
        return self.__description
    
    @property
    def additional_info(self) -> str:
        return self.__additional_info
    
    @property
    def images(self) -> List[str]:
        return self.__images
    
    @property
    def listing_status(self) -> str:
        return self.__listing_status
    
    @property
    def created_at(self) -> str:
        return self.__created_at
    
    @property
    def updated_at(self) -> str:
        return self.__updated_at

    # Setters
    @quantity.setter
    def quantity(self, new_quantity: int) -> None:
        if new_quantity < 0:
            raise ValueError("Quantity cannot be negative")
        self.__quantity = new_quantity
        self.__updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if new_quantity == 0:
            self.__listing_status = "sold_out"

    @listing_status.setter
    def listing_status(self, new_status: str) -> None:
        if new_status not in ['active', 'sold_out', 'removed']:
            raise ValueError("Invalid listing status")
        self.__listing_status = new_status
        self.__updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> Dict:
        # Get base product dictionary from parent class
        base_dict = super().to_dict()
        # Add listed product specific fields
        listing_dict = {
            'category': self.__category,
            'price': self.__price,
            'quantity': self.__quantity,
            'unit': self.__unit,
            'harvest_date': self.__harvest_date,
            'description': self.__description,
            'additional_info': self.__additional_info,
            'images': self.__images,
            'listing_status': self.__listing_status,
            'created_at': self.__created_at,
            'updated_at': self.__updated_at
        }
        # Merge the dictionaries
        return {**base_dict, **listing_dict}

class ListedProductManager:
    def __init__(self, upload_folder: str = 'static/product_images'):
        self.__db_name = 'listed_products_db'
        self.__upload_folder = upload_folder
        self.__file_manager = FileTransactionManager(upload_folder)

    # Need to add in ListedProductManager
    def delete_farmer_products(self, farmer_username: str):
        """Delete all products listed by a farmer"""
        try:
            print(f"Attempting to delete products for farmer: {farmer_username}")
            with self.__get_db() as db:
                if 'farmer_products' in db and farmer_username in db['farmer_products']:
                    print(f"Found products for farmer {farmer_username}")
                    # Get all product images to delete
                    for product_data in db['farmer_products'][farmer_username].values():
                        for image in product_data.get('images', []):
                            self.__file_manager.delete_file(image)
                    
                    # Delete farmer's products entry
                    del db['farmer_products'][farmer_username]
                    print(f"Successfully deleted products for farmer {farmer_username}")
                    
                    # Commit file deletions
                    if self.__file_manager.commit():
                        print("Successfully committed file deletions")
                    else:
                        print("Failed to commit file deletions")
                else:
                    print(f"No products found for farmer {farmer_username}")
        except Exception as e:
            print(f"Error deleting farmer products: {str(e)}")
            import traceback
            traceback.print_exc()
            self.__file_manager.rollback()

    def update_product(self, product_id: str, owner: str, name: str, category: str, 
                      price: float, quantity: int, unit: str, harvest_date: str,
                      expiry_date: str, description: str, additional_info: str = None, 
                      new_images: List = None) -> bool:
        """Update product with transactional file handling"""
        try:
            with self.__get_db() as db:
                if ('farmer_products' not in db or 
                    owner not in db['farmer_products'] or 
                    product_id not in db['farmer_products'][owner]):
                    return False
                
                # Get existing product data
                existing_data = db['farmer_products'][owner][product_id]
                existing_images = existing_data.get('images', [])
                
                # Handle new images if provided
                image_filenames = []
                if new_images and any(file.filename for file in new_images):
                    # Queue deletion of existing images
                    for old_image in existing_images:
                        self.__file_manager.delete_file(old_image)
                    
                    # Queue creation of new images
                    for file in new_images:
                        filename = self.__file_manager.add_file(file)
                        if filename:
                            image_filenames.append(filename)
                else:
                    image_filenames = existing_images
                
                # Create updated product
                product = ListedProduct(
                    id=product_id,
                    name=name,
                    expiry_date=expiry_date,
                    owner=owner,
                    category=category,
                    price=price,
                    quantity=quantity,
                    unit=unit,
                    harvest_date=harvest_date,
                    description=description,
                    additional_info=additional_info,
                    images=image_filenames,
                    listing_status='active' if quantity > 0 else 'sold_out'
                )
                
                # Update database
                db['farmer_products'][owner][product_id] = product.to_dict()
                
                # Commit file operations
                if not self.__file_manager.commit():
                    # Restore original data if file operations fail
                    db['farmer_products'][owner][product_id] = existing_data
                    return False
                
                return True
                
        except Exception as e:
            print(f"Error updating product: {str(e)}")
            self.__file_manager.rollback()
            return False
    
    def __get_db(self):
        return shelve.open(self.__db_name, writeback=True)
    
    def create_product(self, name: str, category: str, price: float, quantity: int,
                  unit: str, harvest_date: str, expiry_date: str, description: str,
                  owner: str, additional_info: str = None, images: List = None) -> str:
        """Create a new listed product with transactional file handling"""
        try:
            # Process images first
            image_filenames = []
            if images:
                for file in images:
                    if file:  # Check if file exists
                        filename = self.__file_manager.add_file(file)
                        if filename:
                            image_filenames.append(filename)
            
            # Create product in database
            with self.__get_db() as db:
                product_id = str(datetime.now().timestamp())
                
                if 'farmer_products' not in db:
                    db['farmer_products'] = {}
                if owner not in db['farmer_products']:
                    db['farmer_products'][owner] = {}
                
                # Create product
                product = ListedProduct(
                    id=product_id,
                    name=name,
                    expiry_date=expiry_date,
                    owner=owner,
                    category=category,
                    price=price,
                    quantity=quantity,
                    unit=unit,
                    harvest_date=harvest_date,
                    description=description,
                    additional_info=additional_info,
                    images=image_filenames
                )
                
                # Store in database
                db['farmer_products'][owner][product_id] = product.to_dict()
                
                # Commit file operations
                if not self.__file_manager.commit():
                    # If file operations failed, remove product from database
                    del db['farmer_products'][owner][product_id]
                    if not db['farmer_products'][owner]:
                        del db['farmer_products'][owner]
                    return None
                
                return product_id
                
        except Exception as e:
            print(f"Error in create_product: {str(e)}")
            self.__file_manager.rollback()
            return None
        
    def delete_product(self, product_id: str, owner: str) -> bool:
        """Delete product with transactional file handling"""
        try:
            with self.__get_db() as db:
                if ('farmer_products' not in db or 
                    owner not in db['farmer_products'] or 
                    product_id not in db['farmer_products'][owner]):
                    return False
                
                # Get product data
                product_data = db['farmer_products'][owner][product_id]
                
                # Queue file deletions
                for filename in product_data.get('images', []):
                    self.__file_manager.delete_file(filename)
                
                # Delete from database
                del db['farmer_products'][owner][product_id]
                if not db['farmer_products'][owner]:
                    del db['farmer_products'][owner]
                
                # Commit file operations
                if not self.__file_manager.commit():
                    # Restore product data if file operations fail
                    db['farmer_products'][owner][product_id] = product_data
                    return False
                
                return True
                
        except Exception as e:
            print(f"Error deleting product: {str(e)}")
            self.__file_manager.rollback()
            return False

    def get_product(self, product_id: str, name: str = None) -> Optional[ListedProduct]:
        """Get a specific product with more robust lookup"""
        try:
            with self.__get_db() as db:
                # First, try direct lookup by product ID
                for farmer_products in db.get('farmer_products', {}).values():
                    if product_id in farmer_products:
                        data = farmer_products[product_id]
                        
                        # Optional name verification if provided
                        if name and data.get('name') != name:
                            print(f"WARNING: Product name mismatch. Expected {name}, Found {data.get('name')}")
                        
                        return ListedProduct(
                            id=data['id'],
                            name=data['name'],
                            expiry_date=data['expiry_date'],
                            owner=data['owner'],
                            category=data['category'],
                            price=data['price'],
                            quantity=data['quantity'],
                            unit=data['unit'],
                            harvest_date=data['harvest_date'],
                            description=data['description'],
                            additional_info=data.get('additional_info'),
                            images=data.get('images', []),
                            listing_status=data.get('listing_status', 'active')
                        )
                
                # If no product found
                print(f"ERROR: Product not found. ID: {product_id}, Name: {name}")
                return None
                    
        except Exception as e:
            print(f"Error getting product: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def get_farmer_products(self, owner: str) -> List[ListedProduct]:
        """Get all products listed by a specific farmer"""
        try:
            with self.__get_db() as db:
                if 'farmer_products' not in db or owner not in db['farmer_products']:
                    return []

                products = []
                for data in db['farmer_products'][owner].values():
                    product = ListedProduct(
                        id=data['id'],
                        name=data['name'],
                        expiry_date=data['expiry_date'],
                        owner=data['owner'],
                        category=data['category'],
                        price=data['price'],
                        quantity=data['quantity'],
                        unit=data['unit'],
                        harvest_date=data['harvest_date'],
                        description=data['description'],
                        additional_info=data.get('additional_info'),
                        images=data.get('images', []),
                        listing_status=data.get('listing_status', 'active')
                    )
                    products.append(product)
                return products

        except Exception as e:
            print(f"Error getting farmer products: {str(e)}")
            return []

    def update_product_quantity(self, product_id: str, owner: str, 
                              new_quantity: int) -> bool:
        """Update product quantity"""
        try:
            with self.__get_db() as db:
                if ('farmer_products' not in db or 
                    owner not in db['farmer_products'] or 
                    product_id not in db['farmer_products'][owner]):
                    return False

                data = db['farmer_products'][owner][product_id]
                product = ListedProduct(
                    id=data['id'],
                    name=data['name'],
                    expiry_date=data['expiry_date'],
                    owner=data['owner'],
                    category=data['category'],
                    price=data['price'],
                    quantity=new_quantity,  # Update quantity
                    unit=data['unit'],
                    harvest_date=data['harvest_date'],
                    description=data['description'],
                    additional_info=data.get('additional_info'),
                    images=data.get('images', []),
                    listing_status=data.get('listing_status', 'active')
                )
                
                db['farmer_products'][owner][product_id] = product.to_dict()
                return True

        except Exception as e:
            print(f"Error updating product quantity: {str(e)}")
            return False
        
@dataclass
class FileOperation:
    """Represents a pending file operation"""
    operation: str  # 'create' or 'delete'
    temp_path: str  # Temporary file path
    final_path: str  # Final file path
    file_obj: Optional[object] = None  # Store the actual file object

class FileTransactionManager:
    def __init__(self, upload_folder: str):
        self.upload_folder = upload_folder
        self.temp_folder = os.path.join(upload_folder, 'temp')
        self.operations: List[FileOperation] = []
        
        # Ensure folders exist
        os.makedirs(self.upload_folder, exist_ok=True)
        os.makedirs(self.temp_folder, exist_ok=True)
    
    def add_file(self, file) -> Optional[str]:
        """Queue a file creation operation"""
        try:
            if hasattr(file, 'filename') and file.filename:  # For FileStorage objects
                # Generate unique filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = secure_filename(file.filename)
                unique_filename = f"{timestamp}_{filename}"
                
                # Set up paths
                temp_path = os.path.join(self.temp_folder, unique_filename)
                final_path = os.path.join(self.upload_folder, unique_filename)
                
                # Save to temp location
                file.save(temp_path)
                
                # Add to pending operations
                self.operations.append(
                    FileOperation('create', temp_path, final_path, file)
                )
                
                return unique_filename
            else:  # For string filenames (existing files)
                return file
                
        except Exception as e:
            print(f"Error in add_file: {str(e)}")
            return None
    
    def delete_file(self, filename: str):
        """Queue a file deletion operation"""
        if filename:
            filepath = os.path.join(self.upload_folder, filename)
            if os.path.exists(filepath):
                self.operations.append(
                    FileOperation('delete', filepath, filepath)
                )
    
    def commit(self) -> bool:
        """Execute all pending file operations"""
        try:
            # Process all operations
            for op in self.operations:
                if op.operation == 'create':
                    # Only move file if it's a new file operation
                    if os.path.exists(op.temp_path):
                        os.rename(op.temp_path, op.final_path)
                elif op.operation == 'delete':
                    if os.path.exists(op.final_path):
                        os.remove(op.final_path)
            return True
            
        except Exception as e:
            print(f"Error in commit: {str(e)}")
            self.rollback()
            return False
            
        finally:
            self.operations.clear()
    
    def rollback(self):
        """Rollback all pending operations"""
        try:
            for op in self.operations:
                if op.operation == 'create':
                    # Remove temp file if it exists
                    if os.path.exists(op.temp_path):
                        os.remove(op.temp_path)
                # No need to handle delete rollback as files haven't been deleted yet
        except Exception as e:
            print(f"Error in rollback: {str(e)}")
        finally:
            self.operations.clear()

"""add to cart"""
class CartItem:
    def __init__(self, product_id: str, quantity: int, name: str, price: float, unit: str):
        self.product_id = product_id
        self.quantity = quantity
        self.name = name
        self.price = price
        self.unit = unit
        self.subtotal = price * quantity
        
        # Get product's current quantity
        listed_product_manager = ListedProductManager()
        product = listed_product_manager.get_product(product_id)
        self.max_quantity = product.quantity if product else quantity

    def to_dict(self) -> dict:
        return {
            'product_id': self.product_id,
            'quantity': self.quantity,
            'name': self.name,
            'price': self.price,
            'unit': self.unit,
            'subtotal': self.subtotal,
            'max_quantity': self.max_quantity
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'CartItem':
        """Create CartItem from dictionary"""
        item = cls(
            product_id=data['product_id'],
            quantity=data['quantity'],
            name=data['name'],
            price=data['price'],
            unit=data['unit']
        )
        # Recalculate subtotal to ensure accuracy
        item.subtotal = item.price * item.quantity
        return item


# In models.py, update the Cart class:

class Cart:
    def __init__(self):
        self.items = {}  # Dictionary of product_id: CartItem
        self.total = 0.0

    def __len__(self):
        return len(self.items)

    def add_item(self, product_id: str, quantity: int, name: str, price: float, unit: str):
        """Add or update item in cart"""
        if product_id in self.items:
            self.items[product_id].quantity += quantity
            self.items[product_id].subtotal = self.items[product_id].quantity * price
        else:
            self.items[product_id] = CartItem(product_id, quantity, name, price, unit)
        self._update_total()

    def remove_item(self, product_id: str):
        """Remove item from cart"""
        if product_id in self.items:
            del self.items[product_id]
            self._update_total()

    def update_quantity(self, product_id: str, quantity: int):
        """Update item quantity"""
        if product_id in self.items:
            if quantity <= 0:
                self.remove_item(product_id)
            else:
                self.items[product_id].quantity = quantity
                self.items[product_id].subtotal = quantity * self.items[product_id].price
                self._update_total()

    def get_items(self) -> list:
        """Get list of cart items"""
        return list(self.items.values())

    def _update_total(self):
        """Update cart total"""
        self.total = sum(item.subtotal for item in self.items.values())

    def to_dict(self) -> dict:
        """Convert cart to dictionary for storage"""
        return {
            'items': {str(pid): item.to_dict() for pid, item in self.items.items()},
            'total': float(self.total)
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Cart':
        """Create cart from dictionary with robust error handling"""
        cart = cls()
        try:
            # Ensure data is a dictionary with 'items' key
            if not isinstance(data, dict) or 'items' not in data:
                return cart
            
            # Safely convert items
            for pid, item_data in data['items'].items():
                try:
                    cart.items[pid] = CartItem.from_dict(item_data)
                except Exception as e:
                    print(f"Error converting cart item {pid}: {e}")
                    continue
            
            # Set total, defaulting to 0 if not present or invalid
            cart.total = float(data.get('total', 0))
            
            # Recalculate total to ensure accuracy
            cart._update_total()
            
            return cart
        
        except Exception as e:
            print(f"Error creating cart from dictionary: {e}")
            return cls()

class CartManager:
    def __init__(self):
        self.__db_name = 'cart_db'
    
    def __get_db(self):
        return shelve.open(self.__db_name, writeback=True)
    
    def get_cart(self, user_id: str) -> Cart:
        """Get user's cart, creating only if not exists"""
        try:
            with self.__get_db() as db:
                # Check if cart exists for this user
                if user_id not in db:
                    cart = Cart()
                    db[user_id] = cart.to_dict()
                    return cart
                
                # Retrieve existing cart
                cart_data = db[user_id]
                
                # Validate cart data structure
                if not isinstance(cart_data, dict):
                    cart = Cart()
                    db[user_id] = cart.to_dict()
                    return cart
                
                # Ensure cart data has required keys
                if 'items' not in cart_data or 'total' not in cart_data:
                    cart = Cart()
                    db[user_id] = cart.to_dict()
                    return cart
                
                # Create Cart from stored dictionary
                cart = Cart.from_dict(cart_data)
                return cart
            
        except Exception as e:
            print(f"Error getting cart for {user_id}: {e}")
            import traceback
            traceback.print_exc()
            return Cart()

    def update_cart(self, user_id: str, cart: Cart):
        """Update cart for a specific user"""
        try:
            with self.__get_db() as db:
                # Store cart as dictionary
                db[user_id] = cart.to_dict()
                db.sync()  # Ensure data is written to disk
        except Exception as e:
            print(f"Error updating cart: {e}")
            import traceback
            traceback.print_exc()

    def clear_cart(self, user_id: str):
        """Clear user's cart"""
        try:
            with self.__get_db() as db:
                if user_id in db:
                    del db[user_id]
                    db.sync()  # Ensure deletion is written to disk
        except Exception as e:
            print(f"Error clearing cart: {e}")
            import traceback
            traceback.print_exc()

class OrderSummary:
    def __init__(self, order_id: str, username: str, items: list, total: float, 
                 shipping_info: dict):
        self.order_id = order_id
        self.username = username
        self.items = items
        self.total = total
        self.shipping_info = shipping_info
        self.created_at = datetime.now()

    def to_dict(self) -> dict:
        return {
            'order_id': self.order_id,
            'username': self.username,
            'items': self.items,
            'total': self.total,
            'shipping_info': self.shipping_info,
            'created_at': self.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
    
class OrderManager:
    def __init__(self):
        self.__db_name = 'orders_db'
    
    def __get_db(self):
        return shelve.open(self.__db_name, writeback=True)
    
    # Need to add in OrderManager
    def delete_farmer_orders(self, farmer_username: str):
        """Delete or update orders related to the farmer"""
        try:
            with self.__get_db() as db:
                if 'orders' not in db:
                    return
                    
                # Get all orders that involve this farmer
                for order_id, order_data in list(db['orders'].items()):
                    if farmer_username in order_data.get('farmer_statuses', {}):
                        # Remove farmer's status from the order
                        del order_data['farmer_statuses'][farmer_username]
                        
                        # Filter out items from this farmer
                        order_data['items'] = [
                            item for item in order_data['items']
                            if item.get('farmer_username') != farmer_username
                        ]
                        
                        # If no items left or no other farmers involved, delete the order
                        if not order_data['items'] or not order_data['farmer_statuses']:
                            del db['orders'][order_id]
                        else:
                            # Update the order with remaining items
                            db['orders'][order_id] = order_data
                            
        except Exception as e:
            print(f"Error deleting farmer orders: {str(e)}")
    
    def delete_order(self, order_id: str, farmer_username: str) -> bool:
        """Delete an order with proper validation"""
        try:
            with self.__get_db() as db:
                # Check if orders exist in db
                if 'orders' not in db:
                    print(f"No orders found in database")
                    return False
                
                # Check if specific order exists
                if order_id not in db['orders']:
                    print(f"Order {order_id} not found")
                    return False
                
                order_data = db['orders'][order_id]
                
                # Verify farmer has items in this order
                farmer_has_items = False
                for item in order_data.get('items', []):
                    # Check if any items belong to this farmer
                    if farmer_username in order_data.get('farmer_statuses', {}):
                        farmer_has_items = True
                        break
                
                if not farmer_has_items:
                    print(f"Farmer {farmer_username} not authorized to delete order {order_id}")
                    return False
                
                # Delete the order
                del db['orders'][order_id]
                db.sync()  # Ensure changes are written to disk
                
                print(f"Successfully deleted order {order_id}")
                return True
                
        except Exception as e:
            print(f"Error deleting order {order_id}: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def update_farmer_order_status(self, order_id: str, farmer_username: str, status: str) -> bool:
        try:
            with self.__get_db() as db:
                if 'orders' not in db or order_id not in db['orders']:
                    return False
                order_data = db['orders'][order_id]
                order_data['farmer_statuses'][farmer_username] = status
                db['orders'][order_id] = order_data
                return True
        except Exception as e:
            print(f"Error updating farmer status: {str(e)}")
            return False
    
    def create_order(self, username: str, cart_items: list, shipping_info: dict, 
                    status: str, farmer_statuses: dict) -> str:
        """Create a new order and transfer cart items"""
        try:
            # Generate a more readable order ID
            order_id = f"ORD-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
            
            order_data = {
                'order_id': order_id,
                'username': username,
                'items': cart_items,  # Now this is already a list of dictionaries
                'total': sum(item['subtotal'] for item in cart_items),
                'shipping_info': shipping_info,
                'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'status': status,
                'farmer_statuses': farmer_statuses,
            }
            
            with self.__get_db() as db:
                # Ensure 'orders' dictionary exists
                if 'orders' not in db:
                    db['orders'] = {}
                
                # Store the order
                db['orders'][order_id] = order_data
                
                # Debug print
                print(f"OrderManager: Created order {order_id} for user {username}")
                print(f"Order details: {order_data}")
                
                return order_id
                
        except Exception as e:
            print(f"Error creating order: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
    
    def finalize_order(self, order_id: str, cart_manager: 'CartManager', username: str) -> bool:
        """Finalize order and clear cart"""
        try:
            with self.__get_db() as db:
                if 'orders' not in db or order_id not in db['orders']:
                    return False
                
                # Update order status to completed
                order_data = db['orders'][order_id]
                order_data['status'] = OrderStatus.COMPLETED
                order_data['completed_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Update the order in the database
                db['orders'][order_id] = order_data
                
                # Clear the user's cart
                cart_manager.clear_cart(username)
                
                return True
                
        except Exception as e:
            print(f"Error finalizing order: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def update_order_status(self, order_id: str, status: str) -> bool:
        """Update the status of an order"""
        try:
            with self.__get_db() as db:
                if 'orders' not in db or order_id not in db['orders']:
                    return False
                
                # Validate status
                if not OrderStatus.is_valid_status(status):
                    raise ValueError(f"Invalid status: {status}")
                
                # Update order status
                order_data = db['orders'][order_id]
                order_data['status'] = status
                order_data['status_updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Update the order in the database
                db['orders'][order_id] = order_data
                
                return True
                
        except Exception as e:
            print(f"Error updating order status: {str(e)}")
            import traceback
            traceback.print_exc()
            return False


class OrderStatus:
    """Enum for order statuses"""
    PENDING = 'pending'
    PROCESSING = 'processing'
    COMPLETED = 'completed'
    CANCELLED = 'cancelled'
    
    @classmethod
    def get_all_statuses(cls):
        return [cls.PENDING, cls.PROCESSING, cls.COMPLETED, cls.CANCELLED]
        
    @classmethod
    def is_valid_status(cls, status):
        return status in cls.get_all_statuses()
    
    
class OTPManager:
    def __init__(self):
        self.__db_name = 'otp_db'
        
    def __get_db(self):
        return shelve.open(self.__db_name)
    
    def generate_otp(self):
        """Generate a 6-digit OTP"""
        return ''.join([str(random.randint(0, 9)) for _ in range(6)])
    
    def store_otp(self, identifier, otp):
        """Store OTP with metadata"""
        try:
            with self.__get_db() as db:
                db[identifier] = {
                    'otp': otp,
                    'expiry': datetime.now() + timedelta(minutes=3),
                    'attempts': 0,
                    'verified': False,
                    'last_sent': datetime.now()
                }
                return True
        except Exception as e:
            print(f"Error storing OTP: {str(e)}")
            return False
    
    def delete_otp(self, identifier):
        """Delete stored OTP for identifier"""
        try:
            with self.__get_db() as db:
                if identifier in db:
                    del db[identifier]
                return True
        except Exception as e:
            print(f"Error deleting OTP: {str(e)}")
            return False
    
    def verify_otp(self, identifier, otp):
        """Verify OTP and handle attempts"""
        try:
            with self.__get_db() as db:
                if identifier not in db:
                    return False, "No OTP found for this identifier"
                
                otp_data = db[identifier]
                
                # Check if OTP has expired
                if datetime.now() > otp_data['expiry']:
                    self.delete_otp(identifier)
                    return False, "OTP has expired"
                
                # Check attempt limit
                if otp_data['attempts'] >= 3:
                    self.delete_otp(identifier)
                    return False, "Too many failed attempts. Please request a new OTP"
                
                # Verify OTP
                if otp_data['otp'] != otp:
                    otp_data['attempts'] += 1
                    db[identifier] = otp_data
                    remaining_attempts = 3 - otp_data['attempts']
                    return False, f"Invalid OTP. {remaining_attempts} attempts remaining"
                
                # Mark as verified
                otp_data['verified'] = True
                db[identifier] = otp_data
                return True, "OTP verified successfully"
                
        except Exception as e:
            print(f"Error verifying OTP: {str(e)}")
            return False, "Error verifying OTP"