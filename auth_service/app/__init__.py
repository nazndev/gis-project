from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from app.config import Config
from app.database import db, init_db
from app.routes.auth_routes import auth_bp
from app.routes.user_routes import user_bp
from app.routes.role_routes import role_bp
from app.routes.permission_routes import permission_bp
from app.utils.logging_config import setup_logging

def create_app():
    """Initialize Flask app and services."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize Services
    db.init_app(app)
    migrate = Migrate(app, db)
    jwt = JWTManager(app)
    logger = setup_logging()

    # Register API Blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(user_bp, url_prefix='/api/users')
    app.register_blueprint(role_bp, url_prefix='/api/roles')
    app.register_blueprint(permission_bp, url_prefix='/api/permissions')

    with app.app_context():
        db.create_all()
        logger.info("Database initialized successfully.")

    logger.info("Auth Service started successfully.")
    return app
