from app import app
import os

port = os.getenv('PORT', '5000')
host = os.getenv('HOST', '0.0.0.0')

app.run(port=port, host=host)