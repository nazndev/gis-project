from flasgger import Swagger
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from app.routes.auth_routes import auth_bp
from app.routes.user_routes import user_bp
from app.routes.role_routes import role_bp
from app.routes.permission_routes import permission_bp
from app.database import db, init_db
from app.utils.logging_config import setup_logging
import os

def create_app():
    """Initialize Flask app, database, and routes."""
    app = Flask(__name__)
    app.config.from_object("app.config.Config")

    # Initialize Services
    init_db(app)
    jwt = JWTManager(app)
    migrate = Migrate(app, db)
    logger = setup_logging()

    # Setup Swagger
    swagger = Swagger(app)

    # Register API Blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(user_bp, url_prefix='/api/users')
    app.register_blueprint(role_bp, url_prefix='/api/roles')
    app.register_blueprint(permission_bp, url_prefix='/api/permissions')

    logger.info("Auth Service started successfully.")
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0', port=5001, debug=True)
