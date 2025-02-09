def success_response(message, data=None):
    """Standard format for successful responses."""
    return {
        "status": "success",
        "message": message,
        "data": data or {}
    }

def error_response(message, error_code=400):
    """Standard format for error responses."""
    return {
        "status": "error",
        "message": message,
        "error_code": error_code
    }