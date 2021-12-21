from flask import render_template
from app import app, db

@app.errorhandler(404)
def page_not_found():
    return "<h1>404</h1><p>The resource could not be found.</p>", 404

@app.errorhandler(403)
def forbidden():
    return "<h1>403</h1><p>Forbidden</p>", 403

@app.errorhandler(404)
def not_found_error():
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error():
    db.session.rollback()
    return render_template('500.html'), 500