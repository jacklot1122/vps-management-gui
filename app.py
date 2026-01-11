#!/usr/bin/env python3
"""
VPS Management GUI - Main Flask Application
A web-based interface for managing VPS servers, screen sessions, logs, and system resources.
"""

import os
import subprocess
import psutil
import secrets
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Simple user storage (in production, use a database)
USERS = {
    'admin': {
        'password': os.environ.get('ADMIN_PASSWORD', 'changeme'),
        'id': '1'
    }
}

class User(UserMixin):
    def __init__(self, username):
        self.id = username
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    if user_id in USERS:
        return User(user_id)
    return None

# =============================================================================
# Authentication Routes
# =============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and USERS[username]['password'] == password:
            user = User(username)
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

# =============================================================================
# Dashboard Routes
# =============================================================================

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

# =============================================================================
# Screen Session Management
# =============================================================================

@app.route('/screens')
@login_required
def screens():
    return render_template('screens.html')

@app.route('/api/screens', methods=['GET'])
@login_required
def get_screens():
    """Get list of all screen sessions"""
    try:
        result = subprocess.run(['screen', '-ls'], capture_output=True, text=True)
        output = result.stdout + result.stderr
        
        screens = []
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if '.' in line and ('Detached' in line or 'Attached' in line):
                parts = line.split('\t')
                if parts:
                    screen_info = parts[0].strip()
                    status = 'Attached' if 'Attached' in line else 'Detached'
                    # Extract PID and name
                    if '.' in screen_info:
                        pid_name = screen_info.split('.')
                        pid = pid_name[0]
                        name = '.'.join(pid_name[1:]) if len(pid_name) > 1 else 'unnamed'
                        screens.append({
                            'pid': pid,
                            'name': name,
                            'full_name': screen_info,
                            'status': status
                        })
        
        return jsonify({'success': True, 'screens': screens})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/screens/create', methods=['POST'])
@login_required
def create_screen():
    """Create a new screen session"""
    data = request.get_json()
    name = data.get('name', f'session_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
    command = data.get('command', '')
    
    try:
        if command:
            subprocess.Popen(['screen', '-dmS', name, 'bash', '-c', command])
        else:
            subprocess.Popen(['screen', '-dmS', name])
        return jsonify({'success': True, 'message': f'Screen "{name}" created successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/screens/<screen_id>/delete', methods=['DELETE'])
@login_required
def delete_screen(screen_id):
    """Delete a screen session"""
    try:
        subprocess.run(['screen', '-S', screen_id, '-X', 'quit'], capture_output=True)
        return jsonify({'success': True, 'message': 'Screen deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/screens/<screen_id>/output', methods=['GET'])
@login_required
def get_screen_output(screen_id):
    """Get screen session output (scrollback buffer)"""
    try:
        # Create a temp file to capture screen output
        temp_file = f'/tmp/screen_capture_{screen_id}'
        subprocess.run(['screen', '-S', screen_id, '-X', 'hardcopy', temp_file], capture_output=True)
        
        if os.path.exists(temp_file):
            with open(temp_file, 'r') as f:
                content = f.read()
            os.remove(temp_file)
            return jsonify({'success': True, 'output': content})
        else:
            return jsonify({'success': False, 'error': 'Could not capture screen output'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/screens/<screen_id>/send', methods=['POST'])
@login_required
def send_to_screen(screen_id):
    """Send a command to a screen session"""
    data = request.get_json()
    command = data.get('command', '')
    
    try:
        # Send command to screen
        subprocess.run(['screen', '-S', screen_id, '-X', 'stuff', f'{command}\n'], capture_output=True)
        return jsonify({'success': True, 'message': 'Command sent'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# =============================================================================
# Log Viewer
# =============================================================================

@app.route('/logs')
@login_required
def logs():
    return render_template('logs.html')

@app.route('/api/logs', methods=['GET'])
@login_required
def get_log_files():
    """Get list of log files"""
    log_dirs = ['/var/log', os.path.expanduser('~/logs')]
    log_files = []
    
    for log_dir in log_dirs:
        if os.path.exists(log_dir):
            try:
                for root, dirs, files in os.walk(log_dir):
                    # Limit depth
                    depth = root.replace(log_dir, '').count(os.sep)
                    if depth < 2:
                        for file in files:
                            if file.endswith('.log') or file in ['syslog', 'auth.log', 'messages', 'dmesg']:
                                filepath = os.path.join(root, file)
                                try:
                                    stat = os.stat(filepath)
                                    log_files.append({
                                        'path': filepath,
                                        'name': file,
                                        'size': stat.st_size,
                                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                                    })
                                except (PermissionError, FileNotFoundError):
                                    pass
            except PermissionError:
                pass
    
    return jsonify({'success': True, 'logs': log_files})

@app.route('/api/logs/read', methods=['POST'])
@login_required
def read_log():
    """Read contents of a log file"""
    data = request.get_json()
    filepath = data.get('path', '')
    lines = data.get('lines', 100)
    
    # Security check - only allow reading from specific directories
    allowed_dirs = ['/var/log', os.path.expanduser('~/logs'), os.path.expanduser('~')]
    if not any(filepath.startswith(d) for d in allowed_dirs):
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        result = subprocess.run(['tail', '-n', str(lines), filepath], capture_output=True, text=True)
        return jsonify({'success': True, 'content': result.stdout, 'error_output': result.stderr})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# =============================================================================
# System Monitoring
# =============================================================================

@app.route('/system')
@login_required
def system():
    return render_template('system.html')

@app.route('/api/system/stats', methods=['GET'])
@login_required
def get_system_stats():
    """Get system resource statistics"""
    try:
        # CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        
        # Memory
        memory = psutil.virtual_memory()
        
        # Disk
        disk = psutil.disk_usage('/')
        
        # Network
        net_io = psutil.net_io_counters()
        
        # Uptime
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        
        # Load average
        load_avg = os.getloadavg()
        
        # Processes
        process_count = len(psutil.pids())
        
        return jsonify({
            'success': True,
            'stats': {
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count,
                    'load_avg': list(load_avg)
                },
                'memory': {
                    'total': memory.total,
                    'used': memory.used,
                    'free': memory.free,
                    'percent': memory.percent
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': disk.percent
                },
                'network': {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv
                },
                'uptime': str(uptime).split('.')[0],
                'boot_time': boot_time.isoformat(),
                'process_count': process_count
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/system/processes', methods=['GET'])
@login_required
def get_processes():
    """Get list of running processes"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
            try:
                pinfo = proc.info
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'user': pinfo['username'],
                    'cpu': pinfo['cpu_percent'],
                    'memory': round(pinfo['memory_percent'], 2),
                    'status': pinfo['status']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x['cpu'] or 0, reverse=True)
        return jsonify({'success': True, 'processes': processes[:50]})  # Top 50
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/system/kill/<int:pid>', methods=['POST'])
@login_required
def kill_process(pid):
    """Kill a process"""
    try:
        process = psutil.Process(pid)
        process.terminate()
        return jsonify({'success': True, 'message': f'Process {pid} terminated'})
    except psutil.NoSuchProcess:
        return jsonify({'success': False, 'error': 'Process not found'})
    except psutil.AccessDenied:
        return jsonify({'success': False, 'error': 'Access denied'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/system/disk-breakdown', methods=['GET'])
@login_required
def get_disk_breakdown():
    """Get disk usage breakdown by directory"""
    try:
        breakdown = []
        home_dir = os.path.expanduser('~')
        
        # Key directories to analyze - use absolute paths
        dirs_to_check = [
            ('Documents', os.path.join(home_dir, 'Documents')),
            ('Downloads', os.path.join(home_dir, 'Downloads')),
            ('Desktop', os.path.join(home_dir, 'Desktop')),
            ('Pictures', os.path.join(home_dir, 'Pictures')),
            ('Music', os.path.join(home_dir, 'Music')),
            ('Movies', os.path.join(home_dir, 'Movies')),
            ('Library', os.path.join(home_dir, 'Library')),
            ('.cache', os.path.join(home_dir, '.cache')),
            ('.local', os.path.join(home_dir, '.local')),
            ('Applications', '/Applications'),
            ('var/log', '/var/log'),
            ('tmp', '/tmp'),
        ]
        
        for name, path in dirs_to_check:
            # Ensure path is absolute and exists
            path = os.path.abspath(os.path.expanduser(path))
            if os.path.exists(path) and os.path.isdir(path):
                try:
                    # Use du command for faster calculation
                    result = subprocess.run(
                        ['du', '-sk', path],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        size_kb = int(result.stdout.split()[0])
                        total_size = size_kb * 1024
                        
                        if total_size > 1024 * 1024:  # Only show if > 1MB
                            breakdown.append({
                                'name': name,
                                'path': path,
                                'size': total_size
                            })
                except (subprocess.TimeoutExpired, ValueError, PermissionError):
                    pass
        
        # Sort by size descending
        breakdown.sort(key=lambda x: x['size'], reverse=True)
        
        # Return top 10
        return jsonify({'success': True, 'breakdown': breakdown[:10]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/system/largest-files', methods=['GET'])
@login_required
def get_largest_files():
    """Get the largest files on the system"""
    try:
        home_dir = os.path.expanduser('~')
        
        # Verify home directory exists
        if not os.path.exists(home_dir):
            return jsonify({'success': False, 'error': 'Home directory not found'})
        
        # Find large files using find command
        # Added -L to follow symlinks and better error handling
        result = subprocess.run(
            ['find', home_dir, '-type', 'f', '-size', '+10M', '-exec', 'ls', '-lh', '{}', '+'],
            capture_output=True,
            text=True,
            timeout=30,
            errors='ignore'
        )
        
        files = []
        if result.stdout.strip():
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 9:
                        size_str = parts[4]
                        filepath = ' '.join(parts[8:])
                        
                        # Convert size string to bytes
                        size_bytes = 0
                        try:
                            if size_str.endswith('G'):
                                size_bytes = float(size_str[:-1]) * 1024 * 1024 * 1024
                            elif size_str.endswith('M'):
                                size_bytes = float(size_str[:-1]) * 1024 * 1024
                            elif size_str.endswith('K'):
                                size_bytes = float(size_str[:-1]) * 1024
                            else:
                                size_bytes = float(size_str)
                        except ValueError:
                            continue
                        
                        files.append({
                            'path': filepath,
                            'name': os.path.basename(filepath),
                            'size': int(size_bytes),
                            'size_str': size_str
                        })
        
        # Sort by size descending and get top 20
        files.sort(key=lambda x: x['size'], reverse=True)
        
        # If stderr has content, include it as a warning
        response = {'success': True, 'files': files[:20]}
        if result.stderr and result.stderr.strip():
            response['warning'] = 'Some files could not be accessed due to permissions'
        
        return jsonify(response)
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Search timed out'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# =============================================================================
# File Browser
# =============================================================================

@app.route('/files')
@login_required
def files():
    return render_template('files.html')

@app.route('/api/files/list', methods=['POST'])
@login_required
def list_files():
    """List files in a directory"""
    data = request.get_json()
    path = data.get('path', '~')
    
    # Expand ~ to home directory
    if path.startswith('~'):
        path = os.path.expanduser(path)
    
    # Get absolute path
    path = os.path.abspath(path)
    
    # Verify the path exists
    if not os.path.exists(path):
        return jsonify({'success': False, 'error': f'Path does not exist: {path}'})
    
    try:
        items = []
        
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            try:
                stat = os.stat(item_path)
                items.append({
                    'name': item,
                    'path': item_path,
                    'is_dir': os.path.isdir(item_path),
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'permissions': oct(stat.st_mode)[-3:]
                })
            except (PermissionError, FileNotFoundError):
                pass
        
        # Sort: directories first, then files
        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        
        return jsonify({
            'success': True,
            'path': path,
            'parent': os.path.dirname(path),
            'items': items
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/files/read', methods=['POST'])
@login_required
def read_file():
    """Read file contents"""
    data = request.get_json()
    path = data.get('path', '')
    
    try:
        with open(path, 'r') as f:
            content = f.read(1024 * 1024)  # Max 1MB
        return jsonify({'success': True, 'content': content})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/files/write', methods=['POST'])
@login_required
def write_file():
    """Write file contents"""
    data = request.get_json()
    path = data.get('path', '')
    content = data.get('content', '')
    
    try:
        with open(path, 'w') as f:
            f.write(content)
        return jsonify({'success': True, 'message': 'File saved'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/files/delete', methods=['POST'])
@login_required
def delete_file():
    """Delete a file or directory"""
    data = request.get_json()
    path = data.get('path', '')
    
    try:
        if os.path.isdir(path):
            import shutil
            shutil.rmtree(path)  # Delete directory and all contents
        else:
            os.remove(path)
        return jsonify({'success': True, 'message': 'Deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/files/download', methods=['GET'])
@login_required
def download_file():
    """Download a file"""
    from flask import send_file
    path = request.args.get('path', '')
    
    try:
        if not os.path.exists(path):
            return jsonify({'success': False, 'error': 'File not found'})
        
        if os.path.isdir(path):
            return jsonify({'success': False, 'error': 'Cannot download directories'})
        
        return send_file(path, as_attachment=True, download_name=os.path.basename(path))
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# =============================================================================
# Command Execution
# =============================================================================

@app.route('/terminal')
@login_required
def terminal():
    return render_template('terminal.html')

@app.route('/api/execute', methods=['POST'])
@login_required
def execute_command():
    """Execute a shell command"""
    data = request.get_json()
    command = data.get('command', '')
    
    # Security: Block dangerous commands
    dangerous = ['rm -rf /', 'mkfs', ':(){:|:&};:', 'dd if=/dev/zero']
    if any(d in command for d in dangerous):
        return jsonify({'success': False, 'error': 'Command blocked for security'})
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        return jsonify({
            'success': True,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Command timed out'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# =============================================================================
# WebSocket Events
# =============================================================================

@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        return False
    emit('connected', {'message': 'Connected to server'})

@socketio.on('request_stats')
def handle_stats_request():
    """Send real-time system stats"""
    try:
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        emit('stats_update', {
            'cpu': cpu_percent,
            'memory': memory.percent
        })
    except Exception as e:
        emit('error', {'message': str(e)})

# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    print("=" * 50)
    print("VPS Management GUI")
    print("=" * 50)
    print(f"Running on http://0.0.0.0:5000")
    print(f"Default login: admin / changeme")
    print("Set ADMIN_PASSWORD environment variable to change password")
    print("=" * 50)
    
    # Use PORT from environment variable (for Railway/Heroku) or default to 5000
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
