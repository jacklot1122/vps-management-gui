"""
SSH Manager - Handles SSH connections to remote VPS
"""
import paramiko
import os
from io import StringIO

class SSHManager:
    def __init__(self):
        self.client = None
        self.sftp = None
        self.connected = False
        self.host = None
        self.username = None
        
    def connect(self, host, username, password=None, key_path=None, key_string=None, port=22):
        """Connect to remote VPS via SSH"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Handle different authentication methods
            if key_string:
                # SSH key provided as string (from environment variable)
                key_file = StringIO(key_string)
                pkey = paramiko.RSAKey.from_private_key(key_file)
                self.client.connect(host, port=port, username=username, pkey=pkey, timeout=10)
            elif key_path and os.path.exists(key_path):
                # SSH key file path
                self.client.connect(host, port=port, username=username, key_filename=key_path, timeout=10)
            elif password:
                # Password authentication
                self.client.connect(host, port=port, username=username, password=password, timeout=10)
            else:
                raise ValueError("No authentication method provided")
            
            self.sftp = self.client.open_sftp()
            self.connected = True
            self.host = host
            self.username = username
            return True
        except Exception as e:
            self.connected = False
            raise e
    
    def disconnect(self):
        """Disconnect from VPS"""
        if self.sftp:
            self.sftp.close()
        if self.client:
            self.client.close()
        self.connected = False
        self.host = None
        self.username = None
    
    def execute(self, command, timeout=30):
        """Execute a command on the remote VPS"""
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        
        return {
            'stdout': stdout.read().decode('utf-8', errors='replace'),
            'stderr': stderr.read().decode('utf-8', errors='replace'),
            'exit_code': exit_code
        }
    
    def list_directory(self, path):
        """List files in a remote directory"""
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        # Expand ~ on remote
        if path.startswith('~'):
            result = self.execute(f'echo {path}')
            path = result['stdout'].strip()
        
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
    
    def read_file(self, path, max_size=1024*1024):
        """Read a file from the remote VPS"""
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        with self.sftp.open(path, 'r') as f:
            return f.read(max_size)
    
    def write_file(self, path, content):
        """Write content to a file on the remote VPS"""
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        with self.sftp.open(path, 'w') as f:
            f.write(content)
    
    def upload_file(self, local_path_or_data, remote_path, is_data=False):
        """Upload a file to the remote VPS"""
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        if is_data:
            with self.sftp.open(remote_path, 'wb') as f:
                f.write(local_path_or_data)
        else:
            self.sftp.put(local_path_or_data, remote_path)
    
    def download_file(self, remote_path):
        """Download a file from the remote VPS"""
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        with self.sftp.open(remote_path, 'rb') as f:
            return f.read()
    
    def delete(self, path, is_dir=False):
        """Delete a file or directory on the remote VPS"""
        if not self.connected:
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
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        result = self.execute('screen -ls')
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
        
        return screens
    
    def create_screen(self, name, command='', folder='~', use_venv=False, install_requirements=False):
        """Create a screen session on remote VPS"""
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        # Expand ~ on remote
        if folder.startswith('~'):
            result = self.execute(f'echo {folder}')
            folder = result['stdout'].strip()
        
        # Build the startup script - use a temp file for complex scripts
        script_lines = [
            '#!/bin/bash',
            f'cd "{folder}" || exit 1',
        ]
        
        if use_venv:
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
                script_lines.extend([
                    'if [ -f "requirements.txt" ]; then',
                    '    echo "Installing requirements..."',
                    '    pip install -r requirements.txt',
                    'fi',
                ])
        
        if command:
            script_lines.append(f'echo "Running: {command}"')
            script_lines.append(command)
        
        # Keep the shell alive after command finishes - this is key for proper detach
        script_lines.append('echo "Command finished. Press Ctrl+A, D to detach or Ctrl+C to exit."')
        script_lines.append('exec bash')
        
        # Write script to temp file
        script_content = '\n'.join(script_lines)
        temp_script = f'/tmp/screen_start_{name}.sh'
        
        # Upload script
        self.write_file(temp_script, script_content)
        self.execute(f'chmod +x {temp_script}')
        
        # Create the screen with the script
        result = self.execute(f'screen -dmS {name} bash {temp_script}')
        
        # Clean up script after a delay (screen has started by then)
        self.execute(f'sleep 1 && rm -f {temp_script} &')
        
        return result['exit_code'] == 0
    
    def delete_screen(self, screen_id):
        """Delete a screen session on remote VPS"""
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        result = self.execute(f'screen -S {screen_id} -X quit')
        return result['exit_code'] == 0
    
    def get_screen_output(self, screen_id):
        """Get output from a screen session"""
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        temp_file = f'/tmp/screen_capture_{screen_id.replace(".", "_")}'
        self.execute(f'screen -S {screen_id} -X hardcopy {temp_file}')
        
        try:
            result = self.execute(f'cat {temp_file}')
            self.execute(f'rm -f {temp_file}')
            return result['stdout']
        except:
            return "Could not capture screen output"
    
    def send_to_screen(self, screen_id, command):
        """Send a command to a screen session"""
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        # Escape special characters
        escaped_command = command.replace('"', '\\"')
        result = self.execute(f'screen -S {screen_id} -X stuff "{escaped_command}\\n"')
        return result['exit_code'] == 0
    
    def get_system_stats(self):
        """Get system stats from remote VPS"""
        if not self.connected:
            raise Exception("Not connected to VPS")
        
        stats = {}
        
        # CPU usage
        result = self.execute("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'")
        try:
            stats['cpu_percent'] = round(float(result['stdout'].strip()), 1)
        except:
            stats['cpu_percent'] = 0
        
        # Memory
        result = self.execute("free -b | grep Mem")
        try:
            parts = result['stdout'].split()
            total = int(parts[1])
            used = int(parts[2])
            stats['memory'] = {
                'total': total,
                'used': used,
                'percent': round((used / total) * 100, 1)
            }
        except:
            stats['memory'] = {'total': 0, 'used': 0, 'percent': 0}
        
        # Disk
        result = self.execute("df -B1 / | tail -1")
        try:
            parts = result['stdout'].split()
            total = int(parts[1])
            used = int(parts[2])
            stats['disk'] = {
                'total': total,
                'used': used,
                'percent': round((used / total) * 100, 1)
            }
        except:
            stats['disk'] = {'total': 0, 'used': 0, 'percent': 0}
        
        # Uptime
        result = self.execute("uptime -p")
        stats['uptime'] = result['stdout'].strip().replace('up ', '')
        
        # Hostname
        result = self.execute("hostname")
        stats['hostname'] = result['stdout'].strip()
        
        return stats


# Global SSH manager instance
ssh_manager = SSHManager()
