# VPS Management GUI

## Project Overview
A Flask-based web application for managing VPS servers, specifically designed for screen session management, log viewing, and system monitoring.

## Tech Stack
- **Backend**: Python 3.x with Flask
- **Frontend**: Bootstrap 5, JavaScript
- **Real-time**: Flask-SocketIO for live updates
- **Authentication**: Flask-Login for security

## Features
- Screen session management (create, delete, view, attach)
- System log viewer
- System resource monitoring (CPU, memory, disk)
- Command execution
- File browser

## Development Guidelines
- Use virtual environment for dependencies
- Run with `python app.py` for development
- Default port: 5000
- Secure all endpoints with authentication

## Project Structure
```
/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── templates/          # HTML templates
├── static/            # CSS, JS assets
└── README.md          # Documentation
```
