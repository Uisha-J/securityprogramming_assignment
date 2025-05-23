from werkzeug.security import generate_password_hash, check_password_hash

#test
plain_password = ""
input_password = ""

# 해싱
hashed_password = generate_password_hash(plain_password)

# 검증 시
check_password_hash(hashed_password, input_password)
