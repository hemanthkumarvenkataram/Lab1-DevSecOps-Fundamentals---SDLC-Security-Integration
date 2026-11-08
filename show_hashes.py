
import json

with open("users.json", "r", encoding="utf-8") as file:
    users = json.load(file)

for user in users:
    print(f"Username: {user['username']}")
    print(f"SHA-256 Hash: {user.get('integrity_hash', 'Not generated')}")
    print("-" * 70)
