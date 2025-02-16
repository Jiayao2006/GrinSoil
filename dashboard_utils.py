# dashboard_utils.py

from flask import session
from datetime import datetime

def get_dashboard_stats(user, product_manager, notification_manager, order_manager=None, listed_product_manager=None):
    """
    Get common dashboard statistics for both farmer and customer dashboards
    """
    stats = {}
    
    # Get product counts
    try:
        stats['product_counts'] = product_manager.get_status_counts(session['username'])
    except Exception as e:
        print(f"Error getting product counts: {str(e)}")
        stats['product_counts'] = {
            'fresh': 0,
            'expiring-soon': 0,
            'expired': 0,
            'total': 0
        }
    
    # Get notifications
    try:
        notifications = notification_manager.get_notifications_for_role(session['role'])
        stats['notification_counts'] = {
            'total': len(notifications),
            'unread': len([n for n in notifications if session['username'] not in n.read_by])
        }
        stats['notifications'] = notifications
    except Exception as e:
        print(f"Error getting notifications: {str(e)}")
        stats['notification_counts'] = {'total': 0, 'unread': 0}
        stats['notifications'] = []
    
    # Get role-specific stats
    if session['role'] == 'Farmer' and listed_product_manager:
        try:
            listed_products = listed_product_manager.get_farmer_products(session['username'])
            listed_products.sort(
                key=lambda x: datetime.strptime(x.created_at, "%Y-%m-%d %H:%M:%S"),
                reverse=True
            )
            stats['farmer_stats'] = {
                'total_products': len(listed_products),
                'active_listings': len([p for p in listed_products if p.listing_status == 'active']),
                'low_stock_items': len([p for p in listed_products if p.quantity < 5])
            }
        except Exception as e:
            print(f"Error getting farmer stats: {str(e)}")
            stats['farmer_stats'] = {
                'total_products': 0,
                'active_listings': 0,
                'low_stock_items': 0
            }
            
    elif session['role'] == 'Customer' and order_manager:
        try:
            orders = order_manager.get_user_orders(session['username'])
            stats['customer_stats'] = {
                'total_orders': len(orders),
                'total_spent': sum(order['total'] for order in orders) if orders else 0
            }
        except Exception as e:
            print(f"Error getting customer stats: {str(e)}")
            stats['customer_stats'] = {
                'total_orders': 0,
                'total_spent': 0
            }
    
    return stats

def get_quick_actions(role):
    """
    Get role-specific quick actions for the dashboard
    """
    if role == 'Farmer':
        return [
            {
                'title': 'Add New Product',
                'icon': 'plus-circle',
                'url': 'list_product',
                'color': 'success'
            },
            {
                'title': 'Check Expiry Dates',
                'icon': 'clock',
                'url': 'farmer_expiry_tracker',
                'color': 'warning'
            },
            {
                'title': 'View Notifications',
                'icon': 'bell',
                'url': 'notifications',
                'color': 'info'
            },
            {
                'title': 'Manage Reviews',
                'icon': 'star',
                'url': 'my_reviews',
                'color': 'primary'
            }
        ]
    else:  # Customer actions
        return [
            {
                'title': 'Browse Products',
                'icon': 'shopping-basket',
                'url': 'shop',
                'color': 'success'
            },
            {
                'title': 'Check Expiry Dates',
                'icon': 'clock',
                'url': 'customer_expiry_tracker',
                'color': 'warning'
            },
            {
                'title': 'Write a Review',
                'icon': 'star',
                'url': 'my_reviews',
                'color': 'primary'
            }
        ]

def validate_dashboard_access(user, required_role):
    """
    Validate user access to dashboard
    Returns tuple of (is_valid, error_message)
    """
    if not user:
        return False, 'User account not found'
        
    if session.get('role') != required_role:
        return False, f'Access denied. {required_role} privileges required.'
        
    return True, None

def format_dashboard_data(user, stats, actions):
    """
    Format dashboard data for template rendering
    """
    return {
        'user': user,
        'product_counts': stats['product_counts'],
        'notification_counts': stats['notification_counts'],
        'notifications': stats['notifications'],
        'quick_actions': actions,
        'role_specific_stats': stats.get('farmer_stats' if user.role == 'Farmer' else 'customer_stats', {})
    }