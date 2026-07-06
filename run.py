import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Debug (and the Werkzeug debugger, which allows code execution) is OFF by
    # default and only enabled when FLASK_DEBUG=1 is set in the environment.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
