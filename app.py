import os
import logging
from flask import Flask

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")

# Import routes after app creation to avoid circular imports
from routes import *

# This file is imported by main.py for gunicorn
# Direct execution is handled by main.py
