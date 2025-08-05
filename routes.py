from flask import render_template, request, jsonify
from app import app
from data.tutorials import TUTORIALS
import re

@app.route('/')
def index():
    """Home page with tutorial overview"""
    return render_template('index.html', tutorials=TUTORIALS)

@app.route('/tutorial/<tutorial_id>')
def tutorial_detail(tutorial_id):
    """Individual tutorial page"""
    tutorial = next((t for t in TUTORIALS if t['id'] == tutorial_id), None)
    if not tutorial:
        return render_template('index.html', tutorials=TUTORIALS, error="Tutorial not found"), 404
    return render_template('tutorial.html', tutorial=tutorial)

@app.route('/search')
def search():
    """Search functionality"""
    query = request.args.get('q', '').strip()
    results = []
    
    if query:
        query_lower = query.lower()
        for tutorial in TUTORIALS:
            # Search in title, description, and content
            if (query_lower in tutorial['title'].lower() or 
                query_lower in tutorial['description'].lower() or
                any(query_lower in step.get('content', '').lower() for step in tutorial.get('steps', []))):
                results.append(tutorial)
    
    return render_template('search.html', query=query, results=results)

@app.context_processor
def utility_processor():
    """Make utility functions available in templates"""
    return dict(enumerate=enumerate, len=len)

@app.errorhandler(404)
def not_found(error):
    return render_template('index.html', tutorials=TUTORIALS, error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('index.html', tutorials=TUTORIALS, error="Internal server error"), 500
