from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# We use a simple JSON file to store shares to emulate persistent VM storage.
import json

STORAGE_FILE = "stored_shares.json"

def get_stored_shares():
    if os.path.exists(STORAGE_FILE):
        with open(STORAGE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_stored_shares(shares):
    with open(STORAGE_FILE, "w") as f:
        json.dump(shares, f)

@app.route('/store_share', methods=['POST'])
def store_share():
    data = request.json
    vault_id = data.get('vault_id', 'default_vault')
    share_string = data.get('share')
    
    if not share_string:
         return jsonify({"error": "No share provided"}), 400
         
    stored_shares = get_stored_shares()
    stored_shares[vault_id] = share_string
    save_stored_shares(stored_shares)
    print(f"[NODE] Stored share for vault: {vault_id}")
    return jsonify({"status": "Stored successfully"}), 200

@app.route('/get_share/<vault_id>', methods=['GET'])
def get_share(vault_id):
    stored_shares = get_stored_shares()
    if vault_id in stored_shares:
        print(f"[NODE] Retrieving share for vault: {vault_id}")
        return jsonify({"share": stored_shares[vault_id]}), 200
    
    print(f"[NODE] Share not found for vault: {vault_id}")
    return jsonify({"error": "Share not found"}), 404

if __name__ == '__main__':
    # Binds to all interfaces inside the container on port 5000
    app.run(host='0.0.0.0', port=5000)
