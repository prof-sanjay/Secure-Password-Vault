import os
import base64
import time
import secrets
import string
import requests
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from vault import Vault
from secret_sharing import generate_shares, recover_secret

app = Flask(__name__)
# Secret key for signing Flask session cookies
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(minutes=5)

# Login attempt memory constraints (track by IP address internally)
login_attempts = {}

# Global vault instance for the local password manager
VAULT_FILE = "vault.json"
vault = Vault(VAULT_FILE)

def is_logged_in():
    # Returns True if the user has unlocked the vault and the key resides in memory
    return session.get('logged_in') and vault.key is not None

@app.before_request
def enforce_security():
    endpoint = request.endpoint
    # Skip enforcement for static assets, login, recover, logout mapping, and the VM fetch API
    if not endpoint or endpoint in ['login', 'recover', 'logout', 'static', 'api_fetch_shares']:
        return
        
    if is_logged_in():
        now = time.time()
        last_active = session.get('last_active', now)
        if now - last_active > 300: # mathematically enforced 5 min timeout
            session.clear()
            vault.key = None 
            flash('Your session expired due to 5 minutes of inactivity.', 'danger')
            return redirect(url_for('login'))
            
        session['last_active'] = now
    else:
        # Fallback projection wrapper to guarantee unauthenticated bounces
        flash('Unauthorized. Please log in first.', 'danger')
        return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('dashboard'))

    ip = request.remote_addr
    attempt_data = login_attempts.get(ip, {'count': 0, 'lockout_until': 0})

    if request.method == 'POST':
        password = request.form.get('master_password')
        try:
            # We check if vault.json exists
            if not os.path.exists(VAULT_FILE):
                # Create a barebone vault if it is entirely new
                start_time = time.perf_counter()
                vault.create(password)
                calc_time = time.perf_counter() - start_time
                session.permanent = True
                session['logged_in'] = True
                session['last_active'] = time.time()
                flash(f'New vault created securely! Key derivation took {calc_time:.3f}s.', 'success')
                return redirect(url_for('dashboard'))

            # Standard Unlock Flow
            start_time = time.perf_counter()
            unlocked = vault.unlock(password)
            calc_time = time.perf_counter() - start_time
            if unlocked:
                # Reset failure blocks
                login_attempts[ip] = {'count': 0, 'lockout_until': 0}
                session.permanent = True
                session['logged_in'] = True
                session['last_active'] = time.time()
                flash(f'Vault decrypted successfully! (Argon2id derivation took {calc_time:.3f}s)', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Security delay logic artificially slowing brute forces
                time.sleep(2)
                attempt_data['count'] += 1
                flash(f'Invalid master password. Total failed attempts: {attempt_data["count"]}', 'danger')
                
                login_attempts[ip] = attempt_data
                return render_template('login.html', vault_exists=os.path.exists(VAULT_FILE), attempts=attempt_data['count'], calc_time=calc_time, memory_mb=64)
        except Exception as e:
            flash(f'Cryptography Error: {str(e)}', 'danger')

    return render_template('login.html', vault_exists=os.path.exists(VAULT_FILE), attempts=attempt_data['count'], calc_time=0, memory_mb=64.0)

@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', entries=vault.entries)

@app.route('/add', methods=['GET', 'POST'])
def add():
    if not is_logged_in():
        return redirect(url_for('login'))

    if request.method == 'POST':
        website = request.form.get('website')
        username = request.form.get('username')
        password = request.form.get('password')
        
        if website and username and password:
            # Re-encrypts the vault instantly upon modification
            vault.add_password(website, username, password)
            flash(f'Credentials for {website} stored securely.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('All fields are required.', 'danger')

    return render_template('add.html')

@app.route('/delete/<int:index>', methods=['POST'])
def delete(index):
    if not is_logged_in():
        return redirect(url_for('login'))
        
    try:
        # The list is 0-indexed in Python but the visual index is 1-indexed.
        # However, our vault.delete_password takes the visual 1-based index!
        vault.delete_password(index)
        flash('Password deleted and vault resealed.', 'success')
    except Exception as e:
        flash('Delete error: ' + str(e), 'danger')
        
    return redirect(url_for('dashboard'))

@app.route('/backup', methods=['GET', 'POST'])
def backup():
    if not is_logged_in():
        return redirect(url_for('login'))

    shares_formatted = None
    if request.method == 'POST':
        try:
            k = int(request.form.get('k'))
            n = int(request.form.get('n'))
            
            if k > n:
                flash('Threshold (k) cannot be greater than total shares (n).', 'danger')
            elif n > 5:
                flash('For this VM demonstration architecture, total shares (n) cannot exceed the 5 configured VM nodes.', 'danger')
            else:
                # Extracts the raw 32-byte AES key from the operational Vault
                # and mathematically splits it into 'n' chunks via Shamir.
                shares = generate_shares(vault.key, k, n)
                shares_formatted = []
                vm_ports = [5001, 5002, 5003, 5004, 5005]
                success_count = 0
                
                for i, (idx, s1, s2) in enumerate(shares):
                    s1_b64 = base64.b64encode(s1).decode()
                    s2_b64 = base64.b64encode(s2).decode()
                    share_str = f"{idx}:{s1_b64}:{s2_b64}"
                    shares_formatted.append(share_str)
                    
                    # DISTRIBUTED VM BACKUP: Push this exact mathematical fragment to an isolated VM
                    try:
                        port = vm_ports[i]
                        requests.post(f"http://127.0.0.1:{port}/store_share", json={
                            "vault_id": "master_vault_demo",
                            "share": share_str
                        }, timeout=2)
                        success_count += 1
                    except Exception as e:
                        print(f"Network error routing share to port {port}: {e}")
                        
                flash(f'Recovery shares successfully distributed! Network successfully routed {success_count} fragments to remote VMs.', 'success')
        except ValueError:
            flash('Please enter valid integers for k and n.', 'danger')

    return render_template('backup.html', shares=shares_formatted)

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    if request.method == 'POST':
        raw_shares = request.form.get('shares').strip().split('\n')
        new_password = request.form.get('new_password')
        
        if not new_password:
            flash('You must assign a new master password upon recovery.', 'danger')
            return render_template('recover.html')

        try:
            parsed_shares = []
            for share_str in raw_shares:
                share_str = share_str.strip()
                if not share_str:
                    continue
                parts = share_str.split(':')
                if len(parts) != 3:
                    continue
                    
                idx = int(parts[0])
                s1 = base64.b64decode(parts[1])
                s2 = base64.b64decode(parts[2])
                parsed_shares.append((idx, s1, s2))
                
            # Perform mathematical Lagrange recreation 
            recovered_key = recover_secret(parsed_shares)
            
            if vault.unlock_with_key(recovered_key):
                # Successfully decrypted via the AES Key. Now re-pack it into a brand new vault envelope.
                current_entries = vault.entries
                vault.create(new_password)
                vault.entries = current_entries
                vault._save()
                
                session.permanent = True
                session['logged_in'] = True
                session['last_active'] = time.time()
                flash('The automated AES recovery succeeded. Vault unlocked and bound to your new master password.', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Recovery failed. Invalid decryption attempt.', 'danger')
        except Exception as e:
            flash(f'Mathematical recovery boundary failure: {str(e)}', 'danger')

    return render_template('recover.html')

@app.route('/logout')
def logout():
    session.clear()
    vault.key = None
    vault.salt = None
    vault.entries = []
    flash('Vault explicitly locked and RAM wiped.', 'success')
    return redirect(url_for('login'))

@app.route('/api/fetch_shares', methods=['GET'])
def api_fetch_shares():
    raw_shares = []
    vm_ports = [5001, 5002, 5003, 5004, 5005]
    for port in vm_ports:
        try:
            resp = requests.get(f"http://127.0.0.1:{port}/get_share/master_vault_demo", timeout=1.5)
            if resp.status_code == 200:
                raw_shares.append(resp.json().get("share"))
        except requests.RequestException:
            continue
            
    if not raw_shares:
        return jsonify({"error": "Unable to reach Virtual Machines or no shares found."}), 503
        
    return jsonify({"shares": raw_shares})

@app.route('/api/generate_password', methods=['GET'])
def api_generate():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    
    length_str = request.args.get('length', '16')
    try:
        length = int(length_str)
        if length < 8: length = 8
    except ValueError:
        length = 16
        
    alphabet = string.ascii_letters + string.digits + string.punctuation
    # Loop guarantees at least one of each class of character is forced for maximum local entropy
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in string.punctuation for c in pwd)):
            break
            
    return jsonify({"password": pwd})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=443, debug=True, ssl_context=('cert.pem', 'key.pem'))
