# Overview

This is an Advanced Ethical Hacking Tutorials web application built with Flask. The application serves as an educational platform for learning penetration testing and cybersecurity techniques using Kali Linux tools. It provides interactive tutorials with step-by-step guides, code examples, and search functionality for various hacking methodologies including network reconnaissance, vulnerability assessment, and security testing.

# User Preferences

Preferred communication style: Simple, everyday language.

# Recent Changes

- 2025-08-05: Successfully migrated project from Replit Agent to Replit environment
- 2025-08-05: Removed Settings tab from bottom navigation across all templates and JavaScript files
- 2025-08-05: Updated theme from dark to light with green-red gradient background
- 2025-08-05: Changed title to "Advanced Ethical Hacking Methods Using Kali Linux – A Practical Guide"
- 2025-08-05: Enhanced navigation with home icon in header and improved mobile responsiveness
- 2025-08-05: Fixed LSP diagnostics and verified all routes are working correctly

# System Architecture

## Frontend Architecture
- **Template Engine**: Jinja2 templates with Flask's built-in templating system
- **UI Framework**: Bootstrap 5 for responsive design and components
- **Styling**: Custom CSS with dark theme and terminal-inspired design using CSS variables
- **JavaScript**: Vanilla JavaScript for interactive features including smooth scrolling, copy code functionality, and search enhancements
- **Syntax Highlighting**: Prism.js for code block highlighting in tutorials
- **Icons**: Font Awesome for consistent iconography

## Backend Architecture
- **Web Framework**: Flask with modular route organization
- **Application Structure**: Simple MVC pattern with separated routes, data, and templates
- **Session Management**: Flask sessions with configurable secret key from environment variables
- **Error Handling**: Custom 404 and 500 error handlers with user-friendly fallbacks
- **Logging**: Python's built-in logging configured for debug level

## Data Storage
- **Content Management**: Static data structure using Python dictionaries for tutorials
- **Data Organization**: Tutorial content stored in `data/tutorials.py` with structured format including steps, code examples, and metadata
- **Search Implementation**: In-memory search across tutorial titles, descriptions, and content using string matching

## Application Features
- **Modular Tutorial System**: Hierarchical tutorial structure with interconnected modules, categories, difficulty levels, and duration estimates
- **Module-Based Learning**: Each tutorial contains multiple linked modules with specific learning objectives and progressive skill building
- **Search Functionality**: Full-text search across all tutorial content with query highlighting
- **Responsive Design**: Mobile-first design approach with Bootstrap grid system
- **Code Examples**: Syntax-highlighted code blocks with copy functionality for security tools and commands
- **Interactive Navigation**: Module-aware sidebar navigation with step grouping by learning modules
- **Safety Warnings**: Prominent legal and ethical disclaimers throughout the application

# External Dependencies

## Frontend Libraries
- **Bootstrap 5**: CSS framework for responsive UI components and layout
- **Font Awesome 6**: Icon library for consistent visual elements
- **Prism.js**: Syntax highlighting library for code blocks

## Python Dependencies
- **Flask**: Core web framework for routing, templating, and request handling
- **Werkzeug**: WSGI utilities (included with Flask) for HTTP request/response handling

## Development Tools
- **Python Logging**: Built-in logging system for application debugging and monitoring
- **Environment Variables**: Configuration management for sensitive data like session secrets

## Content Dependencies
- **Kali Linux Tools**: Application content focuses on tools like nmap, masscan, zmap, and other penetration testing utilities
- **Security Best Practices**: Content emphasizes ethical hacking principles and legal compliance requirements