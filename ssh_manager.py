"""
SSH Manager - Handles SSH connections to remote VPS
"""
import paramiko
from paramiko import SSHException
import os
import logging
import time
import threading
import socket
from io import StringIO

# Configure logging for SSH Manager
logger = logging.getLogger(__name__)

class SSHManager:
    def __init__(self):
        self.client = None
        self.sftp = None
        self.connected = False
        self.host = None
        self.username = None
        self.password = None
        self.key_path = None
        self.key_string = None
        self.port = 22
        self._lock = threading.Lock()
        self._last_activity = time.time()
        
    def _is_connection_alive(self):
        """Check if the SSH connection is still alive"""
        if not self.client or not self.connected:
            return False
        try:
            transport = self.client.get_transport()
            if transport is None or not transport.is_active():
                return False
            # Send a keepalive to check connection
            transport.send_ignore()
            return True
        except Exception as e:
            logger.debug(f"Connection check failed: {e}")
            return False
    
    def ensure_connected(self):
        """Ensure we have a valid connection, reconnect if needed"""
        if not self._is_connection_alive():
            if self.host and self.username:
                logger.info("Connection lost, attempting to reconnect...")
                try:
                    self.disconnect()
                    self.connect(
                        self.host, 
                        self.username, 
                        password=self.password,
                        key_path=self.key_path,
                        key_string=self.key_string,
                        port=self.port
                    )
                    return True
                except Exception as e:
                    logger.error(f"Reconnection failed: {e}")
                    return False
            return False
        return True
        
    def connect(self, host, username, password=None, key_path=None, key_string=None, port=22):
        """Connect to remote VPS via SSH"""
        logger.info(f"SSH connect attempt: host={host}, username={username}, port={port}")
        logger.debug(f"Auth methods: password={'YES' if password else 'NO'}, key_path={'YES' if key_path else 'NO'}, key_string={'YES' if key_string else 'NO'}")
        
        # Store credentials for reconnection
        self.host = host
        self.username = username
        self.password = password
        self.key_path = key_path
        self.key_string = key_string
        self.port = port
        
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Set keepalive to prevent connection drops
            
            # Handle different authentication methods
            if key_string:
                # SSH key provided as string (from environment variable)
                logger.debug("Using SSH key from string")
                key_file = StringIO(key_string)
                pkey = paramiko.RSAKey.from_private_key(key_file)
                self.client.connect(host, port=port, username=username, pkey=pkey, timeout=15, banner_timeout=15)
            elif key_path and os.path.exists(key_path):
                # SSH key file path
                logger.debug(f"Using SSH key from file: {key_path}")
                self.client.connect(host, port=port, username=username, key_filename=key_path, timeout=15, banner_timeout=15)
            elif password:
                # Password authentication
                logger.debug("Using password authentication")
                self.client.connect(host, port=port, username=username, password=password, timeout=15, banner_timeout=15)
            else:
                logger.error("No authentication method provided")
                raise ValueError("No authentication method provided")
            
            # Enable keepalive on the transport
            transport = self.client.get_transport()
            if transport:
                transport.set_keepalive(30)  # Send keepalive every 30 seconds
            
            self.sftp = self.client.open_sftp()
            # Set longer timeout for SFTP operations
            self.sftp.get_channel().settimeout(30)
            
            self.connected = True
            self._last_activity = time.time()
            logger.info(f"SSH connected successfully to {host}")
            return True
        except Exception as e:
            logger.error(f"SSH connection failed: {str(e)}")
            self.connected = False
            raise e
    
    def disconnect(self):
        """Disconnect from VPS"""
        try:
            if self.sftp:
                self.sftp.close()
            if self.client:
                self.client.close()
        except:
            pass
        self.connected = False
        self.client = None
        self.sftp = None
    
    def execute(self, command, timeout=30, retries=2):
        """Execute a command on the remote VPS with retry logic"""
        with self._lock:
            for attempt in range(retries + 1):
                try:
                    if not self.ensure_connected():
                        raise Exception("Not connected to VPS")
                    
                    self._last_activity = time.time()
                    logger.debug(f"SSH execute: {command[:100]}{'...' if len(command) > 100 else ''}")
                    stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
                    exit_code = stdout.channel.recv_exit_status()
                    
                    stdout_text = stdout.read().decode('utf-8', errors='replace')
                    stderr_text = stderr.read().decode('utf-8', errors='replace')
                    
                    logger.debug(f"SSH execute result: exit_code={exit_code}, stdout={stdout_text[:200] if stdout_text else 'empty'}, stderr={stderr_text[:200] if stderr_text else 'empty'}")
                    
                    return {
                        'stdout': stdout_text,
                        'stderr': stderr_text,
                        'exit_code': exit_code
                    }
                except Exception as e:
                    logger.warning(f"Execute attempt {attempt + 1} failed: {e}")
                    if attempt < retries:
                        self.connected = False  # Force reconnect
                        time.sleep(0.5)
                    else:
                        raise
    
    def list_directory(self, path, retries=2):
        """List files in a remote directory with retry logic"""
        # Ensure we're connected before attempting
        if not self.ensure_connected():
            raise Exception("Not connected to VPS")
        
        # Expand ~ on remote
        if path.startswith('~'):
            result = self.execute(f'echo {path}')
            path = result['stdout'].strip()
        
        for attempt in range(retries + 1):
            try:
                items = []
                for attr in self.sftp.listdir_attr(path):
                    items.append({
                        'name': attr.filename,
                        'path': os.path.join(path, attr.filename),
                        'is_dir': attr.st_mode & 0o40000 == 0o40000,  # S_ISDIR
                        'size': attr.st_size,
                        'modified': attr.st_mtime,
                        'permissions': oct(attr.st_mode)[-3:]
                    })
                return path, items
            except FileNotFoundError:
                raise Exception(f"Path does not exist: {path}")
            except PermissionError:
                raise Exception(f"Permission denied: {path}")
            except (EOFError, SSHException, socket.error) as e:
                logger.warning(f"list_directory attempt {attempt + 1} failed: {e}")
                if attempt < retries:
                    self.connected = False
                    if self.ensure_connected():
                        continue
                raise Exception(f"Failed to list directory: {e}")
    
    def read_file(self, path, max_size=1024*1024, retries=2):
        """Read a file from the remote VPS with retry logic"""
        if not self.ensure_connected():
            raise Exception("Not connected to VPS")
        
        for attempt in range(retries + 1):
            try:
                with self.sftp.open(path, 'r') as f:
                    return f.read(max_size)
            except (EOFError, SSHException, socket.error) as e:
                logger.warning(f"read_file attempt {attempt + 1} failed: {e}")
                if attempt < retries:
                    self.connected = False
                    if self.ensure_connected():
                        continue
                raise Exception(f"Failed to read file: {e}")
    
    def write_file(self, path, content, retries=2):
        """Write content to a file on the remote VPS with retry logic"""
        if not self.ensure_connected():
            raise Exception("Not connected to VPS")
        
        for attempt in range(retries + 1):
            try:
                with self.sftp.open(path, 'w') as f:
                    f.write(content)
                return
            except (EOFError, SSHException, socket.error) as e:
                logger.warning(f"write_file attempt {attempt + 1} failed: {e}")
                if attempt < retries:
                    self.connected = False
                    if self.ensure_connected():
                        continue
                raise Exception(f"Failed to write file: {e}")
    
    def upload_file(self, local_path_or_data, remote_path, is_data=False, retries=2):
        """Upload a file to the remote VPS with retry logic"""
        if not self.ensure_connected():
            raise Exception("Not connected to VPS")
        
        for attempt in range(retries + 1):
            try:
                if is_data:
                    with self.sftp.open(remote_path, 'wb') as f:
                        f.write(local_path_or_data)
                else:
                    self.sftp.put(local_path_or_data, remote_path)
                return
            except (EOFError, SSHException, socket.error) as e:
                logger.warning(f"upload_file attempt {attempt + 1} failed: {e}")
                if attempt < retries:
                    self.connected = False
                    if self.ensure_connected():
                        continue
                raise Exception(f"Failed to upload file: {e}")
    
    def download_file(self, remote_path, retries=2):
        """Download a file from the remote VPS with retry logic"""
        if not self.ensure_connected():
            raise Exception("Not connected to VPS")
        
        for attempt in range(retries + 1):
            try:
                with self.sftp.open(remote_path, 'rb') as f:
                    return f.read()
            except (EOFError, SSHException, socket.error) as e:
                logger.warning(f"download_file attempt {attempt + 1} failed: {e}")
                if attempt < retries:
                    self.connected = False
                    if self.ensure_connected():
                        continue
                raise Exception(f"Failed to download file: {e}")
    
    def delete(self, path, is_dir=False, retries=2):
        """Delete a file or directory on the remote VPS with retry logic"""
        if not self.ensure_connected():
            raise Exception("Not connected to VPS")
        
        if is_dir:
            # Use rm -rf for directories
            result = self.execute(f'rm -rf "{path}"')
            if result['exit_code'] != 0:
                raise Exception(result['stderr'])
        else:
            self.sftp.remove(path)
    
    def path_exists(self, path):
        """Check if a path exists on the remote VPS"""
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        try:
            self.sftp.stat(path)
            return True
        except FileNotFoundError:
            return False
    
    def get_home_directory(self):
        """Get the home directory on the remote VPS"""
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        result = self.execute('echo $HOME')
        return result['stdout'].strip()
    
    def get_screens(self):
        """Get list of screen sessions on remote VPS"""
        logger.debug("get_screens() called")
        if not self.connected:
            logger.error("get_screens() called but not connected to VPS")
            raise Exception("Not connected to VPS")
        
        # Try to list all screens (for current user)
        result = self.execute('screen -ls')
        logger.debug(f"screen -ls raw output: {result['stdout']}")
        
        # Also try to find screens for all users if running as root
        all_screens_result = self.execute('ls -la /run/screen/ 2>/dev/null || echo "no screen dir"')
        logger.debug(f"Screen directories: {all_screens_result['stdout']}")
        
        screens = []
        
        for line in result['stdout'].split('\n'):
            line = line.strip()
            if '.' in line and ('Attached' in line or 'Detached' in line):
                parts = line.split('\t')
                if len(parts) >= 2:
                    full_name = parts[0].strip()
                    status = 'Attached' if 'Attached' in line else 'Detached'
                    
                    # Parse PID and name
                    name_parts = full_name.split('.')
                    pid = name_parts[0] if len(name_parts) > 0 else ''
                    name = '.'.join(name_parts[1:]) if len(name_parts) > 1 else full_name
                    
                    screens.append({
                        'pid': pid,
                        'name': name,
                        'full_name': full_name,
                        'status': status
                    })
        
        logger.info(f"get_screens() found {len(screens)} screens: {screens}")
        return screens
    
    def create_screen(self, name, command='', folder='~', use_venv=False, install_requirements=False):
        """Create a screen session on remote VPS"""
        logger.info(f"create_screen() called: name={name}, command={command}, folder={folder}, use_venv={use_venv}, install_requirements={install_requirements}")
        
        if not self.connected:
            logger.error("create_screen() called but not connected to VPS")
            raise Exception("Not connected to VPS")
        
        # Expand ~ on remote
        if folder.startswith('~'):
            logger.debug(f"Expanding folder path: {folder}")
            result = self.execute(f'echo {folder}')
            folder = result['stdout'].strip()
            logger.debug(f"Expanded folder path: {folder}")
        
        # Build the startup script - use a temp file for complex scripts
        script_lines = [
            '#!/bin/bash',
            f'cd "{folder}" || exit 1',
        ]
        
        if use_venv:
            logger.debug("Adding venv setup to script")
            script_lines.extend([
                'if [ ! -d ".venv" ] && [ ! -d "venv" ]; then',
                '    echo "Creating virtual environment..."',
                '    python3 -m venv .venv',
                'fi',
                'if [ -d ".venv" ]; then',
                '    echo "Activating .venv..."',
                '    source .venv/bin/activate',
                'elif [ -d "venv" ]; then',
                '    echo "Activating venv..."',
                '    source venv/bin/activate',
                'fi',
            ])
            
            if install_requirements:
                logger.debug("Adding requirements install to script")
                script_lines.extend([
                    'if [ -f "requirements.txt" ]; then',
                    '    echo "Installing requirements..."',
                    '    pip install -r requirements.txt',
                    'fi',
                ])
        
        if command:
            logger.debug(f"Adding command to script: {command}")
            # Fix commands with unquoted filenames containing special characters
            # Pattern: "python filename.py" or "node script.js" etc where filename may have spaces/parens
            import re
            
            # Match: interpreter + space + filename (which may contain spaces/special chars)
            # Common patterns: python file.py, python3 file.py, node file.js, bash file.sh
            match = re.match(r'^(python3?|node|bash|sh|ruby|perl)\s+(.+\.(?:py|js|sh|rb|pl))(\s+.*)?$', command, re.IGNORECASE)
            if match:
                interpreter = match.group(1)
                filename = match.group(2)
                extra_args = match.group(3) or ''
                # Quote the filename if it contains special characters
                if any(c in filename for c in ' ()[]{}$&;|<>\'\"'):
                    safe_command = f'{interpreter} "{filename}"{extra_args}'
                else:
                    safe_command = command
                logger.debug(f"Pattern matched - safe command: {safe_command}")
            else:
                # No pattern match, use command as-is
                safe_command = command
                logger.debug(f"No pattern match, using original command")
            
            script_lines.append(f'echo "Running: {command}"')
            script_lines.append(safe_command)
        
        # Keep the shell alive after command finishes - this is key for proper detach
        script_lines.append('echo "Command finished. Press Ctrl+A, D to detach or Ctrl+C to exit."')
        script_lines.append('exec bash')
        
        # Write script to temp file
        script_content = '\n'.join(script_lines)
        logger.debug(f"Script content:\\n{script_content}")
        
        # Sanitize name for use in filenames and screen names (remove/replace special chars)
        import re
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
        logger.debug(f"Sanitized screen name: '{name}' -> '{safe_name}'")
        
        temp_script = f'/tmp/screen_start_{safe_name}.sh'
        logger.debug(f"Temp script path: {temp_script}")
        
        # Upload script
        logger.debug("Writing script to temp file on VPS...")
        try:
            self.write_file(temp_script, script_content)
            logger.debug("Script written successfully")
        except Exception as e:
            logger.error(f"Failed to write script: {e}")
            raise
        
        logger.debug("Making script executable...")
        chmod_result = self.execute(f'chmod +x "{temp_script}"')
        logger.debug(f"chmod result: {chmod_result}")
        
        # Verify script exists
        verify_result = self.execute(f'cat "{temp_script}"')
        logger.debug(f"Script verification: exists={verify_result['exit_code'] == 0}, content_len={len(verify_result['stdout'])}")
        
        # Create the screen with the script - use sanitized name for screen too
        screen_cmd = f'screen -dmS "{safe_name}" bash "{temp_script}"'
        logger.info(f"Creating screen with command: {screen_cmd}")
        result = self.execute(screen_cmd)
        logger.info(f"Screen create result: exit_code={result['exit_code']}, stdout={result['stdout']}, stderr={result['stderr']}")
        
        # Check if screen was actually created
        import time
        time.sleep(0.5)
        verify_screens = self.execute('screen -ls')
        logger.debug(f"Screens after creation: {verify_screens['stdout']}")
        
        # Clean up script after a delay (screen has started by then)
        self.execute(f'sleep 1 && rm -f "{temp_script}" &')
        
        success = result['exit_code'] == 0
        logger.info(f"create_screen() returning: {success}")
        return success
    
    def delete_screen(self, screen_id):
        """Delete a screen session on remote VPS"""
        logger.info(f"delete_screen() called: screen_id={screen_id}")
        if not self.connected:
            logger.error("delete_screen() called but not connected to VPS")
            raise Exception("Not connected to VPS")
        
        result = self.execute(f'screen -S "{screen_id}" -X quit')
        logger.debug(f"delete_screen result: exit_code={result['exit_code']}")
        return result['exit_code'] == 0
    
    def get_screen_output(self, screen_id):
        """Get output from a screen session"""
        logger.debug(f"get_screen_output() called: screen_id={screen_id}")
        if not self.connected:
            logger.error("get_screen_output() called but not connected to VPS")
            raise Exception("Not connected to VPS")
        
        # Sanitize screen_id for use in temp filename
        import re
        safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', screen_id)
        temp_file = f'/tmp/screen_capture_{safe_id}'
        self.execute(f'screen -S "{screen_id}" -X hardcopy "{temp_file}"')
        
        try:
            result = self.execute(f'cat "{temp_file}"')
            self.execute(f'rm -f "{temp_file}"')
            logger.debug(f"get_screen_output() returning {len(result['stdout'])} chars")
            return result['stdout']
        except Exception as e:
            logger.error(f"get_screen_output() failed: {e}")
            return "Could not capture screen output"
    
    def send_to_screen(self, screen_id, command):
        """Send a command to a screen session"""
        logger.debug(f"send_to_screen() called: screen_id={screen_id}, command={command}")
        if not self.connected:
            logger.error("send_to_screen() called but not connected to VPS")
            raise Exception("Not connected to VPS")
        
        # Escape special characters
        escaped_command = command.replace('"', '\\"')
        result = self.execute(f'screen -S "{screen_id}" -X stuff "{escaped_command}\\n"')
        return result['exit_code'] == 0
    
    def get_system_stats(self):
        """Get system stats from remote VPS"""
        logger.debug("get_system_stats() called")
        if not self.connected:
            logger.error("get_system_stats() called but not connected to VPS")
            raise Exception("Not connected to VPS")
        
        stats = {}
        
        # CPU usage
        logger.debug("Getting CPU stats...")
        result = self.execute("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'")
        try:
            stats['cpu_percent'] = round(float(result['stdout'].strip()), 1)
            logger.debug(f"CPU: {stats['cpu_percent']}%")
        except Exception as e:
            logger.error(f"Failed to parse CPU stats: {e}")
            stats['cpu_percent'] = 0
        
        # Memory
        logger.debug("Getting memory stats...")
        result = self.execute("free -b | grep Mem")
        try:
            parts = result['stdout'].split()
            logger.debug(f"Memory raw parts: {parts}")
            total = int(parts[1])
            used = int(parts[2])
            stats['memory'] = {
                'total': total,
                'used': used,
                'percent': round((used / total) * 100, 1)
            }
            logger.debug(f"Memory: {stats['memory']}")
        except Exception as e:
            logger.error(f"Failed to parse memory stats: {e}")
            stats['memory'] = {'total': 0, 'used': 0, 'percent': 0}
        
        # Disk
        logger.debug("Getting disk stats...")
        result = self.execute("df -B1 / | tail -1")
        try:
            parts = result['stdout'].split()
            logger.debug(f"Disk raw parts: {parts}")
            total = int(parts[1])
            used = int(parts[2])
            stats['disk'] = {
                'total': total,
                'used': used,
                'percent': round((used / total) * 100, 1)
            }
            logger.debug(f"Disk: {stats['disk']}")
        except Exception as e:
            logger.error(f"Failed to parse disk stats: {e}")
            stats['disk'] = {'total': 0, 'used': 0, 'percent': 0}
        
        # Uptime
        logger.debug("Getting uptime...")
        result = self.execute("uptime -p")
        stats['uptime'] = result['stdout'].strip().replace('up ', '')
        logger.debug(f"Uptime: {stats['uptime']}")
        
        # Hostname
        result = self.execute("hostname")
        stats['hostname'] = result['stdout'].strip()
        logger.debug(f"Hostname: {stats['hostname']}")
        
        logger.info(f"get_system_stats() returning: cpu={stats['cpu_percent']}%, mem={stats['memory']['percent']}%, disk={stats['disk']['percent']}%")
        return stats


# Global SSH manager instance
ssh_manager = SSHManager()
