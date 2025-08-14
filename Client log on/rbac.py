# rbac.py

# Define roles and their permissions
ROLE_PERMISSIONS = {
    "admin": ["access_dashboard", "view_logs", "shutdown_server"],
    "user": ["access_dashboard"],
    "guest": []
}

def has_permission(role, permission):
    return permission in ROLE_PERMISSIONS.get(role, [])