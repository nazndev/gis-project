from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import logging

db = SQLAlchemy()
migrate = Migrate()

def init_db(app):
    try:
        db.init_app(app)
        migrate.init_app(app, db)
        with app.app_context():
            db.create_all()
        logging.info("Database successfully initialized.")
    except Exception as e:
        logging.error(f"Database initialization failed: {str(e)}")
