from flask import Flask, request, jsonify, session, send_file
from dotenv import load_dotenv
import os
from functools import wraps
import secrets
from Crypto.Protocol.SecretSharing import Shamir
import base64
import pyotp
import qrcode
from io import BytesIO

load_dotenv()

app = Flask(__name__, static_url_path='')
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')

# The secret to protect the inner chamber (must be hex string)
default_secret = secrets.token_hex(16)  # Generate a random 32-character hex string
CHAMBER_SECRET = os.getenv('CHAMBER_SECRET', default_secret)
# Number of shards needed to reconstruct the secret
THRESHOLD = 3
# Total number of shards
TOTAL_SHARDS = 5

def generate_shards():
    """Generate shards of the secret using Shamir's Secret Sharing"""
    # Convert hex string to bytes
    secret_bytes = bytes.fromhex(CHAMBER_SECRET)
    # Pad the secret if needed (Shamir requires at least 16 bytes)
    if len(secret_bytes) < 16:
        secret_bytes = secret_bytes.ljust(16, b'\0')
    # Generate shares
    shares = Shamir.split(THRESHOLD, TOTAL_SHARDS, secret_bytes)
    # Convert shares to base64 for safe storage/transmission
    return [f"{idx}:{base64.b64encode(share).decode('utf-8')}" for idx, share in shares]

# Generate shards when server starts
SHARDS = generate_shards()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session or not session['authenticated']:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/cos')
def cos():
    return app.send_static_file('cos.html')

@app.route('/secure')
@login_required
def secure():
    return app.send_static_file('secure.html')

@app.route('/api/verify-shards', methods=['POST'])
def verify_shards():
    """Verify submitted shards to reconstruct the secret"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data received'}), 400
        
    submitted_shards = data.get('shards', [])
    print(f"Received shards: {submitted_shards}")  # Debug print
    
    if len(submitted_shards) < THRESHOLD:
        return jsonify({
            'error': f'Not enough shards. Need {THRESHOLD}, got {len(submitted_shards)}'
        }), 400
    
    try:
        # Parse shares back into tuples of (index, bytes)
        shares = []
        for i, shard in enumerate(submitted_shards[:THRESHOLD]):
            try:
                print(f"Processing shard {i + 1}: {shard}")  # Debug print
                
                # Check if the shard is a string
                if not isinstance(shard, str):
                    return jsonify({'error': f'Shard {i + 1} is not a string'}), 400
                
                # Check if the shard contains both index and share
                if ':' not in shard:
                    return jsonify({'error': f'Shard {i + 1} missing colon separator'}), 400
                    
                # Split into index and share
                idx_str, share_b64 = shard.split(':', 1)
                
                # Convert index to integer
                try:
                    idx = int(idx_str)
                    if idx < 1 or idx > TOTAL_SHARDS:
                        return jsonify({'error': f'Shard {i + 1} has invalid index: {idx}'}), 400
                except ValueError:
                    return jsonify({'error': f'Shard {i + 1} has invalid index format: {idx_str}'}), 400
                    
                # Decode base64 share
                try:
                    share_bytes = base64.b64decode(share_b64)
                except Exception as e:
                    return jsonify({'error': f'Shard {i + 1} has invalid base64 encoding: {str(e)}'}), 400
                    
                shares.append((idx, share_bytes))
                print(f"Successfully processed shard {i + 1}")  # Debug print
                
            except Exception as e:
                return jsonify({'error': f'Error processing shard {i + 1}: {str(e)}'}), 400
        
        print(f"All shards processed, attempting reconstruction")  # Debug print
        # Reconstruct the secret
        reconstructed = Shamir.combine(shares)
        # Remove padding
        reconstructed = reconstructed.rstrip(b'\0')
        reconstructed_hex = reconstructed.hex()
        
        if reconstructed_hex == CHAMBER_SECRET:
            session['authenticated'] = True
            return jsonify({'message': 'Chamber unlocked successfully'})
        else:
            return jsonify({'error': 'Invalid combination of shards'}), 400
            
    except Exception as e:
        return jsonify({'error': f'Error combining shards: {str(e)}'}), 400

@app.route('/api/setup-totp')
def setup_totp():
    """Generate QR code for Google Authenticator setup"""
    TOTP_SECRET = os.getenv('TOTP_SECRET', pyotp.random_base32())
    totp = pyotp.TOTP(TOTP_SECRET)
    provisioning_uri = totp.provisioning_uri("Chamber of Secrets", issuer_name="Karthik's Website")
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save QR code to bytes
    img_buffer = BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    return send_file(img_buffer, mimetype='image/png')

@app.route('/api/verify-totp', methods=['POST'])
def verify_totp():
    """Verify TOTP code from Google Authenticator"""
    data = request.get_json()
    submitted_code = data.get('code')
    
    if not submitted_code:
        return jsonify({'error': 'No code provided'}), 400
    
    TOTP_SECRET = os.getenv('TOTP_SECRET', pyotp.random_base32())
    totp = pyotp.TOTP(TOTP_SECRET)
    
    if totp.verify(submitted_code):
        session['authenticated'] = True
        return jsonify({'message': 'Code verified successfully'})
    else:
        return jsonify({'error': 'Invalid code'}), 400

if __name__ == '__main__':
    # Print the shards when starting the server (for testing)
    print("\nChamber Shards (keep these secret and distributed):")
    for i, shard in enumerate(SHARDS, 1):
        print(f"Shard {i}: {shard}")
    print(f"\nNeed {THRESHOLD} of these {TOTAL_SHARDS} shards to unlock the chamber")
    # Print the TOTP secret key when starting the server
    print(f"\nTOTP Secret Key: {os.getenv('TOTP_SECRET', pyotp.random_base32())}\n")
    app.run(debug=True)
