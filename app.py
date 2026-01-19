#!/usr/bin/env python3
"""
VPS Management GUI - Main Flask Application
A web-based interface for managing VPS servers, screen sessions, logs, and system resources.
"""

# Eventlet monkey patching - must be at the very top
import eventlet
eventlet.monkey_patch()

import os
import subprocess
import psutil
import secrets
import logging
import json
import uuid
import hashlib
import hmac
import re
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from ssh_manager import ssh_manager, SSHManager

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# VPS Connection settings from environment variables
VPS_HOST = os.environ.get('VPS_HOST', '')
VPS_USER = os.environ.get('VPS_USER', 'root')
VPS_PASSWORD = os.environ.get('VPS_PASSWORD', '')
VPS_SSH_KEY = os.environ.get('VPS_SSH_KEY', '')  # Private key as string

# Initialize SocketIO with eventlet for production
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

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

# Deployment storage file path
DEPLOYMENTS_FILE = os.environ.get('DEPLOYMENTS_FILE', '/tmp/deployments.json')
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', secrets.token_hex(16))

def load_deployments():
    """Load deployments from JSON file"""
    try:
        if os.path.exists(DEPLOYMENTS_FILE):
            with open(DEPLOYMENTS_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading deployments: {e}")
    return {}

def save_deployments(deployments):
    """Save deployments to JSON file"""
    try:
        with open(DEPLOYMENTS_FILE, 'w') as f:
            json.dump(deployments, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving deployments: {e}")
        return False

def sanitize_screen_name(name):
    """Sanitize screen name to only allow safe characters"""
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name)

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
    if ssh_manager.connected:
        ssh_manager.disconnect()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

# =============================================================================
# VPS Connection Management
# =============================================================================

def ensure_vps_connection():
    """Ensure we're connected to the VPS, return JSON error response if not"""
    logger.debug(f"ensure_vps_connection called. Connected: {ssh_manager.connected}")
    
    if ssh_manager.connected:
        logger.debug("Already connected to VPS")
        return None
    
    if not VPS_HOST:
        logger.warning("VPS_HOST not configured")
        return jsonify({
            'success': False, 
            'error': 'VPS not configured. Go to Settings to configure your VPS connection, or set VPS_HOST, VPS_USER, and VPS_PASSWORD environment variables.'
        })
    
    logger.info(f"Attempting to connect to VPS: {VPS_HOST} as {VPS_USER}")
    try:
        ssh_manager.connect(
            host=VPS_HOST,
            username=VPS_USER,
            password=VPS_PASSWORD if VPS_PASSWORD else None,
            key_string=VPS_SSH_KEY if VPS_SSH_KEY else None
        )
        logger.info(f"Successfully connected to VPS: {VPS_HOST}")
        return None
    except Exception as e:
        logger.error(f"Failed to connect to VPS: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Failed to connect to VPS ({VPS_HOST}): {str(e)}'
        })

@app.route('/api/vps/status', methods=['GET'])
@login_required
def vps_status():
    """Check VPS connection status"""
    if ssh_manager.connected:
        return jsonify({
            'success': True,
            'connected': True,
            'host': ssh_manager.host,
            'user': ssh_manager.username,
            'port': 22
        })
    else:
        return jsonify({
            'success': True,
            'connected': False,
            'configured': bool(VPS_HOST),
            'host': VPS_HOST,
            'user': VPS_USER,
            'port': 22
        })

@app.route('/api/vps/connect', methods=['POST'])
@login_required
def vps_connect():
    """Connect to VPS with provided or environment credentials"""
    data = request.get_json() or {}
    
    # Use provided values or fall back to environment variables
    host = data.get('host') or VPS_HOST
    user = data.get('user') or VPS_USER
    port = int(data.get('port', 22))
    password = data.get('password') or VPS_PASSWORD
    ssh_key = data.get('ssh_key') or VPS_SSH_KEY
    
    if not host:
        return jsonify({'success': False, 'error': 'No VPS host provided'})
    
    try:
        # Disconnect first if already connected
        if ssh_manager.connected:
            ssh_manager.disconnect()
        
        ssh_manager.connect(host, user, password=password, key_string=ssh_key, port=port)
        return jsonify({'success': True, 'message': f'Connected to {host}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/vps/test', methods=['POST'])
@login_required
def vps_test():
    """Test VPS connection without saving"""
    data = request.get_json() or {}
    
    host = data.get('host')
    user = data.get('user', 'root')
    port = int(data.get('port', 22))
    password = data.get('password')
    ssh_key = data.get('ssh_key')
    
    if not host:
        return jsonify({'success': False, 'error': 'No host provided'})
    
    # Create a temporary SSH manager for testing
    test_manager = SSHManager()
    try:
        test_manager.connect(host, user, password=password, key_string=ssh_key, port=port)
        # Test with a simple command
        result = test_manager.execute('echo "Connection successful"')
        test_manager.disconnect()
        return jsonify({'success': True, 'message': 'Connection successful'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/vps/disconnect', methods=['POST'])
@login_required
def vps_disconnect():
    """Disconnect from VPS"""
    if ssh_manager.connected:
        ssh_manager.disconnect()
    return jsonify({'success': True, 'message': 'Disconnected'})

@app.route('/settings')
@login_required
def settings():
    """VPS Settings page"""
    return render_template('settings.html')

# =============================================================================
# Dashboard Routes
# =============================================================================

@app.route('/')
@login_required
def dashboard():
    # Auto-connect to VPS on dashboard load
    ensure_vps_connection()
    return render_template('dashboard.html', vps_host=VPS_HOST, vps_connected=ssh_manager.connected)

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
    """Get list of all screen sessions from remote VPS"""
    logger.debug("GET /api/screens called")
    error = ensure_vps_connection()
    if error:
        logger.error("VPS connection failed in get_screens")
        return jsonify({'success': False, 'error': error})
    
    try:
        screens = ssh_manager.get_screens()
        logger.debug(f"Found {len(screens)} screens: {screens}")
        return jsonify({'success': True, 'screens': screens})
    except Exception as e:
        logger.error(f"Error getting screens: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/screens/create', methods=['POST'])
@login_required
def create_screen():
    """Create a new screen session on remote VPS"""
    logger.info("POST /api/screens/create called")
    
    error = ensure_vps_connection()
    if error:
        logger.error("VPS connection failed in create_screen")
        return jsonify({'success': False, 'error': error})
    
    data = request.get_json()
    logger.debug(f"Request data: {data}")
    
    name = data.get('name', f'session_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
    command = data.get('command', '')
    folder = data.get('folder', '~')
    use_venv = data.get('use_venv', False)
    install_requirements = data.get('install_requirements', False)
    
    logger.info(f"Creating screen: name={name}, command={command}, folder={folder}, use_venv={use_venv}, install_requirements={install_requirements}")
    
    try:
        success = ssh_manager.create_screen(
            name=name,
            command=command,
            folder=folder,
            use_venv=use_venv,
            install_requirements=install_requirements
        )
        logger.info(f"create_screen returned: {success}")
        
        if success:
            return jsonify({'success': True, 'message': f'Screen "{name}" created successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to create screen session'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/screens/<screen_id>/delete', methods=['DELETE'])
@login_required
def delete_screen(screen_id):
    """Delete a screen session on remote VPS"""
    error = ensure_vps_connection()
    if error:
        return jsonify({'success': False, 'error': error})
    
    try:
        ssh_manager.delete_screen(screen_id)
        return jsonify({'success': True, 'message': 'Screen deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/screens/<screen_id>/output', methods=['GET'])
@login_required
def get_screen_output(screen_id):
    """Get screen session output from remote VPS"""
    error = ensure_vps_connection()
    if error:
        return jsonify({'success': False, 'error': error})
    
    try:
        output = ssh_manager.get_screen_output(screen_id)
        return jsonify({'success': True, 'output': output})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/screens/<screen_id>/send', methods=['POST'])
@login_required
def send_to_screen(screen_id):
    """Send a command to a screen session on remote VPS"""
    error = ensure_vps_connection()
    if error:
        return jsonify({'success': False, 'error': error})
    
    data = request.get_json()
    command = data.get('command', '')
    
    try:
        ssh_manager.send_to_screen(screen_id, command)
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
    """Get list of log files from remote VPS"""
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        # Search for log files on remote VPS
        cmd = '''find /var/log -maxdepth 2 -type f \\( -name "*.log" -o -name "syslog" -o -name "auth.log" -o -name "messages" -o -name "dmesg" \\) 2>/dev/null | head -50'''
        result = ssh_manager.execute(cmd)
        
        log_files = []
        for filepath in result['stdout'].strip().split('\n'):
            if filepath:
                # Get file stats
                stat_cmd = f'stat -c "%s %Y" "{filepath}" 2>/dev/null'
                stat_result = ssh_manager.execute(stat_cmd)
                if stat_result['stdout'].strip():
                    parts = stat_result['stdout'].strip().split()
                    if len(parts) >= 2:
                        log_files.append({
                            'path': filepath,
                            'name': os.path.basename(filepath),
                            'size': int(parts[0]),
                            'modified': datetime.fromtimestamp(int(parts[1])).isoformat()
                        })
        
        return jsonify({'success': True, 'logs': log_files})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/logs/read', methods=['POST'])
@login_required
def read_log():
    """Read contents of a log file from remote VPS"""
    data = request.get_json()
    filepath = data.get('path', '')
    lines = data.get('lines', 100)
    
    # Security check - only allow reading from specific directories
    allowed_dirs = ['/var/log', '/root', '/home']
    if not any(filepath.startswith(d) for d in allowed_dirs):
        return jsonify({'success': False, 'error': 'Access denied'})
    
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        result = ssh_manager.execute(f'tail -n {lines} "{filepath}"')
        return jsonify({
            'success': True, 
            'content': result['stdout'], 
            'error_output': result['stderr']
        })
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
    """Get system resource statistics from remote VPS"""
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        stats = {
            'cpu': {'percent': 0, 'count': 1, 'load_avg': [0, 0, 0]},
            'memory': {'total': 0, 'used': 0, 'free': 0, 'percent': 0},
            'disk': {'total': 0, 'used': 0, 'free': 0, 'percent': 0},
            'network': {'bytes_sent': 0, 'bytes_recv': 0, 'packets_sent': 0, 'packets_recv': 0},
            'uptime': 'Unknown',
            'boot_time': '',
            'process_count': 0
        }
        
        # CPU count
        result = ssh_manager.execute('nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo')
        try:
            stats['cpu']['count'] = int(result['stdout'].strip())
        except:
            stats['cpu']['count'] = 1
        
        # Load average
        result = ssh_manager.execute('cat /proc/loadavg')
        try:
            parts = result['stdout'].strip().split()
            stats['cpu']['load_avg'] = [float(parts[0]), float(parts[1]), float(parts[2])]
            # Use load avg as rough CPU percent (load / cores * 100, capped at 100)
            stats['cpu']['percent'] = min(100, round(float(parts[0]) / stats['cpu']['count'] * 100, 1))
        except:
            pass
        
        # Memory
        result = ssh_manager.execute('free -b | grep Mem')
        try:
            parts = result['stdout'].strip().split()
            if len(parts) >= 3:
                total = int(parts[1])
                used = int(parts[2])
                stats['memory'] = {
                    'total': total,
                    'used': used,
                    'free': total - used,
                    'percent': round(used / total * 100, 1) if total > 0 else 0
                }
        except:
            pass
        
        # Disk
        result = ssh_manager.execute('df -B1 / | tail -1')
        try:
            parts = result['stdout'].strip().split()
            if len(parts) >= 5:
                stats['disk'] = {
                    'total': int(parts[1]),
                    'used': int(parts[2]),
                    'free': int(parts[3]),
                    'percent': int(parts[4].replace('%', ''))
                }
        except:
            pass
        
        # Network - try multiple interface names
        result = ssh_manager.execute('cat /proc/net/dev | grep -E "eth0|ens|enp" | head -1')
        try:
            parts = result['stdout'].strip().split()
            if len(parts) >= 10:
                stats['network']['bytes_recv'] = int(parts[1])
                stats['network']['bytes_sent'] = int(parts[9])
        except:
            pass
        
        # Uptime
        result = ssh_manager.execute('uptime -s 2>/dev/null || cat /proc/uptime')
        try:
            boot_str = result['stdout'].strip()
            if ' ' in boot_str and '-' in boot_str:
                # uptime -s format: 2025-01-10 15:30:00
                boot_time = datetime.strptime(boot_str, '%Y-%m-%d %H:%M:%S')
                uptime = datetime.now() - boot_time
                stats['uptime'] = str(uptime).split('.')[0]
                stats['boot_time'] = boot_str
            else:
                # /proc/uptime format: seconds.fraction
                uptime_secs = float(boot_str.split()[0])
                days = int(uptime_secs // 86400)
                hours = int((uptime_secs % 86400) // 3600)
                mins = int((uptime_secs % 3600) // 60)
                stats['uptime'] = f'{days}d {hours}h {mins}m'
        except:
            pass
        
        # Process count
        result = ssh_manager.execute('ps aux | wc -l')
        try:
            stats['process_count'] = int(result['stdout'].strip()) - 1  # Subtract header
        except:
            pass
        
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/system/processes', methods=['GET'])
@login_required
def get_processes():
    """Get list of running processes from remote VPS"""
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        cmd = "ps aux --sort=-%cpu | head -51 | tail -50 | awk '{print $2, $1, $3, $4, $8, $11}'"
        result = ssh_manager.execute(cmd)
        
        processes = []
        for line in result['stdout'].strip().split('\n'):
            parts = line.split(None, 5)
            if len(parts) >= 5:
                processes.append({
                    'pid': int(parts[0]),
                    'user': parts[1],
                    'cpu': float(parts[2]),
                    'memory': float(parts[3]),
                    'status': parts[4],
                    'name': parts[5] if len(parts) > 5 else 'unknown'
                })
        
        return jsonify({'success': True, 'processes': processes})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/system/kill/<int:pid>', methods=['POST'])
@login_required
def kill_process(pid):
    """Kill a process on remote VPS"""
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        result = ssh_manager.execute(f'kill -15 {pid}')
        if result['exit_code'] == 0:
            return jsonify({'success': True, 'message': f'Process {pid} terminated'})
        else:
            return jsonify({'success': False, 'error': result['stderr'] or 'Failed to kill process'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/system/disk-breakdown', methods=['GET'])
@login_required
def get_disk_breakdown():
    """Get disk usage breakdown by directory from remote VPS"""
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        # Get home directory first
        home_result = ssh_manager.execute('echo $HOME')
        home_dir = home_result['stdout'].strip()
        
        # VPS-friendly directories
        dirs_to_check = [
            ('home', home_dir),
            ('var/log', '/var/log'),
            ('tmp', '/tmp'),
            ('opt', '/opt'),
            ('usr/local', '/usr/local'),
            ('var/www', '/var/www'),
            ('var/lib', '/var/lib'),
        ]
        
        breakdown = []
        for name, path in dirs_to_check:
            result = ssh_manager.execute(f'du -sk "{path}" 2>/dev/null | head -1')
            if result['stdout'].strip():
                parts = result['stdout'].strip().split()
                if parts:
                    try:
                        size_kb = int(parts[0])
                        total_size = size_kb * 1024
                        if total_size > 1024 * 1024:  # Only show if > 1MB
                            breakdown.append({
                                'name': name,
                                'path': path,
                                'size': total_size
                            })
                    except ValueError:
                        pass
        
        breakdown.sort(key=lambda x: x['size'], reverse=True)
        return jsonify({'success': True, 'breakdown': breakdown[:10]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/system/largest-files', methods=['GET'])
@login_required
def get_largest_files():
    """Get the largest files on remote VPS"""
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        # Find large files
        cmd = 'find / -type f -size +10M -exec ls -lh {} + 2>/dev/null | sort -k5 -rh | head -30'
        result = ssh_manager.execute(cmd, timeout=60)
        
        files = []
        if result['stdout'].strip():
            for line in result['stdout'].strip().split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 9:
                        size_str = parts[4]
                        filepath = ' '.join(parts[8:])
                        
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
        
        files.sort(key=lambda x: x['size'], reverse=True)
        return jsonify({'success': True, 'files': files[:20]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
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
    """List files in a directory on remote VPS"""
    data = request.get_json()
    path = data.get('path', '~')
    
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        actual_path, items = ssh_manager.list_directory(path)
        
        # Format timestamps
        for item in items:
            item['modified'] = datetime.fromtimestamp(item['modified']).isoformat()
        
        # Sort: directories first, then files
        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        
        # Get parent path
        parent = os.path.dirname(actual_path)
        
        return jsonify({
            'success': True,
            'path': actual_path,
            'parent': parent,
            'items': items
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/files/read', methods=['POST'])
@login_required
def read_file_content():
    """Read file contents from remote VPS"""
    data = request.get_json()
    path = data.get('path', '')
    
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        content = ssh_manager.read_file(path)
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='replace')
        return jsonify({'success': True, 'content': content})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/files/write', methods=['POST'])
@login_required
def write_file():
    """Write file contents to remote VPS"""
    data = request.get_json()
    path = data.get('path', '')
    content = data.get('content', '')
    
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        ssh_manager.write_file(path, content)
        return jsonify({'success': True, 'message': 'File saved'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/files/mkdir', methods=['POST'])
@login_required
def mkdir():
    """Create a directory on remote VPS"""
    data = request.get_json()
    path = data.get('path', '')
    
    if not path:
        return jsonify({'success': False, 'error': 'Path is required'})
    
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        result = ssh_manager.execute(f'mkdir -p "{path}"')
        if result['exit_code'] == 0:
            return jsonify({'success': True, 'message': 'Directory created'})
        else:
            return jsonify({'success': False, 'error': result['stderr'] or 'Failed to create directory'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/files/delete', methods=['POST'])
@login_required
def delete_file():
    """Delete a file or directory on remote VPS"""
    data = request.get_json()
    path = data.get('path', '')
    
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        # Check if it's a directory
        result = ssh_manager.execute(f'test -d "{path}" && echo "dir" || echo "file"')
        is_dir = result['stdout'].strip() == 'dir'
        
        ssh_manager.delete(path, is_dir=is_dir)
        return jsonify({'success': True, 'message': 'Deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/files/download', methods=['GET'])
@login_required
def download_file():
    """Download a file from remote VPS"""
    from flask import Response
    path = request.args.get('path', '')
    
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        # Check if path exists and is a file
        result = ssh_manager.execute(f'test -f "{path}" && echo "exists"')
        if result['stdout'].strip() != 'exists':
            return jsonify({'success': False, 'error': 'File not found or is a directory'})
        
        # Download file content
        content = ssh_manager.download_file(path)
        filename = os.path.basename(path)
        
        return Response(
            content,
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'application/octet-stream'
            }
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/files/upload', methods=['POST'])
@login_required
def upload_file():
    """Upload a file to remote VPS"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'})
    
    file = request.files['file']
    path = request.form.get('path', '~')
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})
    
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        # Expand ~ on remote
        if path.startswith('~'):
            result = ssh_manager.execute(f'echo {path}')
            path = result['stdout'].strip()
        
        # Ensure directory exists
        ssh_manager.execute(f'mkdir -p "{path}"')
        
        # Secure the filename
        from werkzeug.utils import secure_filename
        filename = secure_filename(file.filename)
        remote_path = os.path.join(path, filename)
        
        # Upload file data
        file_data = file.read()
        ssh_manager.upload_file(file_data, remote_path, is_data=True)
        
        return jsonify({
            'success': True, 
            'message': f'File uploaded successfully',
            'filename': filename,
            'filepath': remote_path
        })
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
    """Execute a shell command on remote VPS"""
    data = request.get_json()
    command = data.get('command', '')
    
    # Security: Block dangerous commands
    dangerous = ['rm -rf /', 'mkfs', ':(){:|:&};:', 'dd if=/dev/zero']
    if any(d in command for d in dangerous):
        return jsonify({'success': False, 'error': 'Command blocked for security'})
    
    error = ensure_vps_connection()
    if error:
        return error
    
    try:
        result = ssh_manager.execute(command, timeout=30)
        return jsonify({
            'success': True,
            'stdout': result['stdout'],
            'stderr': result['stderr'],
            'returncode': result['exit_code']
        })
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
    """Send real-time system stats from remote VPS"""
    try:
        if not ssh_manager.connected:
            # Try to connect
            host = os.environ.get('VPS_HOST')
            user = os.environ.get('VPS_USER', 'root')
            password = os.environ.get('VPS_PASSWORD')
            ssh_key = os.environ.get('VPS_SSH_KEY')
            
            if host:
                try:
                    ssh_manager.connect(host, user, password=password, key_string=ssh_key)
                except:
                    emit('error', {'message': 'VPS not connected'})
                    return
            else:
                emit('error', {'message': 'VPS not configured'})
                return
        
        # Get CPU and memory from remote
        cmd = '''grep -c ^processor /proc/cpuinfo && free | grep Mem | awk '{print $3/$2 * 100}' '''
        result = ssh_manager.execute(cmd, timeout=5)
        lines = result['stdout'].strip().split('\n')
        
        cpu = 0
        memory = 0
        if len(lines) >= 2:
            try:
                memory = float(lines[1])
            except:
                pass
        
        # Get load average as CPU indicator
        load_result = ssh_manager.execute('cat /proc/loadavg | awk "{print \\$1}"', timeout=5)
        try:
            cpu = float(load_result['stdout'].strip()) * 10  # Scale load avg
        except:
            pass
        
        emit('stats_update', {
            'cpu': min(cpu, 100),  # Cap at 100%
            'memory': memory
        })
    except Exception as e:
        emit('error', {'message': str(e)})

# =============================================================================
# GitHub Auto-Deploy Routes
# =============================================================================

@app.route('/deployments')
@login_required
def deployments():
    """GitHub Deployments page"""
    # Build the webhook URL
    webhook_url = request.host_url.rstrip('/') + '/webhook/github'
    return render_template('deployments.html', webhook_url=webhook_url)

@app.route('/api/deployments', methods=['GET'])
@login_required
def get_deployments():
    """Get all deployment configurations"""
    deployments = load_deployments()
    return jsonify({'success': True, 'deployments': list(deployments.values())})

@app.route('/api/deployments', methods=['POST'])
@login_required
def add_deployment():
    """Add a new deployment configuration"""
    data = request.get_json()
    
    # Validate required fields
    required = ['repo_url', 'branch', 'deploy_path', 'main_file', 'screen_name']
    for field in required:
        if not data.get(field):
            return jsonify({'success': False, 'error': f'Missing required field: {field}'})
    
    # Generate ID
    deployment_id = str(uuid.uuid4())[:8]
    
    # Sanitize screen name
    data['screen_name'] = sanitize_screen_name(data['screen_name'])
    
    # Build deployment config
    deployment = {
        'id': deployment_id,
        'repo_url': data['repo_url'],
        'branch': data.get('branch', 'main'),
        'deploy_path': data['deploy_path'],
        'main_file': data['main_file'],
        'screen_name': data['screen_name'],
        'interpreter': data.get('interpreter', 'python3'),
        'use_venv': data.get('use_venv', False),
        'venv_path': data.get('venv_path', ''),
        'conda_env': data.get('conda_env', ''),
        'install_deps': data.get('install_deps', False),
        'requirements_file': data.get('requirements_file', 'requirements.txt'),
        'pre_commands': data.get('pre_commands', ''),
        'post_commands': data.get('post_commands', ''),
        'extra_args': data.get('extra_args', ''),
        'working_dir': data.get('working_dir', ''),
        'enabled': data.get('enabled', True),
        'created_at': datetime.now().isoformat(),
        'last_deploy': None,
        'last_log': ''
    }
    
    deployments = load_deployments()
    deployments[deployment_id] = deployment
    save_deployments(deployments)
    
    logger.info(f"Added deployment: {deployment_id} for {data['repo_url']}")
    return jsonify({'success': True, 'deployment': deployment})

@app.route('/api/deployments/<deployment_id>', methods=['GET'])
@login_required
def get_deployment(deployment_id):
    """Get a single deployment configuration"""
    deployments = load_deployments()
    if deployment_id in deployments:
        return jsonify({'success': True, 'deployment': deployments[deployment_id]})
    return jsonify({'success': False, 'error': 'Deployment not found'})

@app.route('/api/deployments/<deployment_id>', methods=['PUT'])
@login_required
def update_deployment(deployment_id):
    """Update a deployment configuration"""
    deployments = load_deployments()
    if deployment_id not in deployments:
        return jsonify({'success': False, 'error': 'Deployment not found'})
    
    data = request.get_json()
    deployment = deployments[deployment_id]
    
    # Update fields
    if 'screen_name' in data:
        data['screen_name'] = sanitize_screen_name(data['screen_name'])
    
    for key in ['repo_url', 'branch', 'deploy_path', 'main_file', 'screen_name', 
                'interpreter', 'use_venv', 'venv_path', 'conda_env', 'install_deps',
                'requirements_file', 'pre_commands', 'post_commands', 'extra_args',
                'working_dir', 'enabled']:
        if key in data:
            deployment[key] = data[key]
    
    deployments[deployment_id] = deployment
    save_deployments(deployments)
    
    return jsonify({'success': True, 'deployment': deployment})

@app.route('/api/deployments/<deployment_id>', methods=['DELETE'])
@login_required
def delete_deployment(deployment_id):
    """Delete a deployment configuration"""
    deployments = load_deployments()
    if deployment_id in deployments:
        del deployments[deployment_id]
        save_deployments(deployments)
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Deployment not found'})

@app.route('/api/deployments/<deployment_id>/log', methods=['GET'])
@login_required
def get_deployment_log(deployment_id):
    """Get the last deployment log"""
    deployments = load_deployments()
    if deployment_id in deployments:
        return jsonify({'success': True, 'log': deployments[deployment_id].get('last_log', '')})
    return jsonify({'success': False, 'error': 'Deployment not found'})

@app.route('/api/deployments/<deployment_id>/deploy', methods=['POST'])
@login_required
def trigger_deployment(deployment_id):
    """Manually trigger a deployment"""
    return execute_deployment(deployment_id)

def execute_deployment(deployment_id):
    """Execute the deployment process"""
    deployments = load_deployments()
    if deployment_id not in deployments:
        return jsonify({'success': False, 'error': 'Deployment not found'})
    
    deployment = deployments[deployment_id]
    log_lines = []
    
    def log(msg):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        line = f"[{timestamp}] {msg}"
        log_lines.append(line)
        logger.info(f"Deploy {deployment_id}: {msg}")
    
    try:
        error = ensure_vps_connection()
        if error:
            log(f"ERROR: VPS connection failed: {error}")
            raise Exception(error)
        
        log(f"Starting deployment for {deployment['repo_url']}")
        
        # 1. Kill existing screen if it exists
        screen_name = deployment['screen_name']
        log(f"Stopping existing screen: {screen_name}")
        ssh_manager.execute(f'screen -X -S "{screen_name}" quit', timeout=10)
        
        # 2. Run pre-deploy commands
        if deployment.get('pre_commands'):
            log("Running pre-deploy commands...")
            for cmd in deployment['pre_commands'].strip().split('\n'):
                if cmd.strip():
                    log(f"  $ {cmd.strip()}")
                    result = ssh_manager.execute(cmd.strip(), timeout=60)
                    if result['stderr']:
                        log(f"  stderr: {result['stderr']}")
        
        # 3. Clone or pull repository
        deploy_path = deployment['deploy_path']
        repo_url = deployment['repo_url']
        branch = deployment['branch']
        
        # Check if directory exists
        check_result = ssh_manager.execute(f'test -d "{deploy_path}/.git" && echo "exists" || echo "new"', timeout=10)
        
        if 'exists' in check_result['stdout']:
            # Pull latest changes
            log(f"Pulling latest changes from {branch}...")
            pull_cmd = f'cd "{deploy_path}" && git fetch origin && git reset --hard origin/{branch}'
            result = ssh_manager.execute(pull_cmd, timeout=120)
            log(f"  {result['stdout'].strip()}")
            if result['stderr'] and 'error' in result['stderr'].lower():
                log(f"  stderr: {result['stderr']}")
        else:
            # Clone repository
            log(f"Cloning repository to {deploy_path}...")
            clone_cmd = f'git clone -b {branch} "{repo_url}" "{deploy_path}"'
            result = ssh_manager.execute(clone_cmd, timeout=300)
            log(f"  {result['stdout'].strip()}")
            if result['exit_code'] != 0:
                log(f"  ERROR: {result['stderr']}")
                raise Exception(f"Clone failed: {result['stderr']}")
        
        # 4. Install dependencies if enabled
        if deployment.get('install_deps'):
            log("Installing dependencies...")
            req_file = deployment.get('requirements_file', 'requirements.txt')
            
            if deployment.get('use_venv'):
                if deployment.get('conda_env'):
                    pip_cmd = f'conda run -n {deployment["conda_env"]} pip install -r "{deploy_path}/{req_file}"'
                elif deployment.get('venv_path'):
                    pip_cmd = f'source "{deployment["venv_path"]}/bin/activate" && pip install -r "{deploy_path}/{req_file}"'
                else:
                    pip_cmd = f'pip install -r "{deploy_path}/{req_file}"'
            else:
                pip_cmd = f'pip install -r "{deploy_path}/{req_file}"'
            
            result = ssh_manager.execute(pip_cmd, timeout=300)
            log(f"  Dependencies installed")
            if result['stderr'] and 'error' in result['stderr'].lower():
                log(f"  Warning: {result['stderr'][:200]}")
        
        # 5. Run post-deploy commands
        if deployment.get('post_commands'):
            log("Running post-deploy commands...")
            for cmd in deployment['post_commands'].strip().split('\n'):
                if cmd.strip():
                    log(f"  $ {cmd.strip()}")
                    result = ssh_manager.execute(cmd.strip(), timeout=60)
                    if result['stderr']:
                        log(f"  stderr: {result['stderr']}")
        
        # 6. Build the run command
        working_dir = deployment.get('working_dir') or deploy_path
        main_file = deployment['main_file']
        interpreter = deployment['interpreter']
        extra_args = deployment.get('extra_args', '')
        
        # Build the full command
        if deployment.get('use_venv'):
            if deployment.get('conda_env'):
                run_cmd = f'conda run -n {deployment["conda_env"]} {interpreter} "{main_file}" {extra_args}'
            elif deployment.get('venv_path'):
                run_cmd = f'source "{deployment["venv_path"]}/bin/activate" && {interpreter} "{main_file}" {extra_args}'
            else:
                run_cmd = f'{interpreter} "{main_file}" {extra_args}'
        else:
            run_cmd = f'{interpreter} "{main_file}" {extra_args}'
        
        # 7. Start new screen session
        log(f"Starting screen session: {screen_name}")
        log(f"  Command: {run_cmd}")
        
        # Create the screen with the command
        screen_cmd = f'cd "{working_dir}" && screen -dmS "{screen_name}" bash -c \'{run_cmd}; exec bash\''
        result = ssh_manager.execute(screen_cmd, timeout=30)
        
        if result['exit_code'] != 0:
            log(f"  ERROR: Failed to start screen: {result['stderr']}")
            raise Exception(f"Screen start failed: {result['stderr']}")
        
        # Verify screen is running
        verify_result = ssh_manager.execute('screen -ls', timeout=10)
        if screen_name in verify_result['stdout']:
            log(f"SUCCESS: Screen '{screen_name}' is now running!")
        else:
            log(f"WARNING: Screen may not have started correctly")
            log(f"  screen -ls output: {verify_result['stdout']}")
        
        # Update deployment record
        deployment['last_deploy'] = datetime.now().isoformat()
        deployment['last_log'] = '\n'.join(log_lines)
        deployments[deployment_id] = deployment
        save_deployments(deployments)
        
        return jsonify({'success': True, 'log': '\n'.join(log_lines)})
        
    except Exception as e:
        log(f"FAILED: {str(e)}")
        deployment['last_log'] = '\n'.join(log_lines)
        deployments[deployment_id] = deployment
        save_deployments(deployments)
        return jsonify({'success': False, 'error': str(e), 'log': '\n'.join(log_lines)})

@app.route('/webhook/github', methods=['POST'])
def github_webhook():
    """Handle GitHub webhook for auto-deploy"""
    logger.info("Received GitHub webhook")
    
    # Get the payload
    payload = request.get_json()
    if not payload:
        return jsonify({'error': 'No payload'}), 400
    
    # Extract repo info
    repo_url = payload.get('repository', {}).get('html_url', '')
    clone_url = payload.get('repository', {}).get('clone_url', '')
    ref = payload.get('ref', '')  # e.g., refs/heads/main
    branch = ref.replace('refs/heads/', '') if ref.startswith('refs/heads/') else ''
    
    logger.info(f"Webhook: repo={repo_url}, branch={branch}")
    
    if not repo_url or not branch:
        return jsonify({'error': 'Invalid payload'}), 400
    
    # Find matching deployments
    deployments = load_deployments()
    triggered = []
    
    for dep_id, dep in deployments.items():
        if not dep.get('enabled'):
            continue
        
        # Match by repo URL (handle both https and git@ formats)
        dep_repo = dep.get('repo_url', '').rstrip('.git')
        if repo_url.rstrip('.git') == dep_repo or clone_url.rstrip('.git') == dep_repo:
            if dep.get('branch', 'main') == branch:
                logger.info(f"Triggering deployment: {dep_id}")
                result = execute_deployment(dep_id)
                triggered.append(dep_id)
    
    if triggered:
        return jsonify({'success': True, 'triggered': triggered})
    else:
        logger.info("No matching deployments found")
        return jsonify({'success': True, 'message': 'No matching deployments'})

# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    print("=" * 50)
    print("VPS Management GUI")
    print("=" * 50)
    print(f"Default login: admin / changeme")
    print("Set ADMIN_PASSWORD environment variable to change password")
    print("=" * 50)
    
    # Use PORT from environment variable (for Railway/Heroku) or default to 5000
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    
    print(f"Starting on port {port}...")
    socketio.run(app, host='0.0.0.0', port=port, debug=debug)
