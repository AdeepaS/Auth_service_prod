import bcrypt

password = "admin123"
hash_str = "$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVKIvi"

is_match = bcrypt.checkpw(password.encode('utf-8'), hash_str.encode('utf-8'))
print(f"Match: {is_match}")
