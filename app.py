from flask import Flask, request, jsonify, render_template, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# 환경 설정
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'  # JWT 서명용 키
db = SQLAlchemy(app)
jwt = JWTManager(app)


# 모델 정의
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)


@app.before_first_request
def create_tables():
    db.create_all()


# 회원가입
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('이미 존재하는 아이디입니다.')
            return redirect('/signup')

        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash('회원가입 성공!')
        return redirect('/login')

    return render_template('signup.html')


# 로그인 → JWT 발급
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash('아이디 또는 비밀번호가 틀렸습니다.')
            return redirect('/login')

        # JWT 토큰 발급
        access_token = create_access_token(identity=user.id)
        return jsonify(message="로그인 성공", access_token=access_token)

    return render_template('login.html')


# 보호된 라우트 예시
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify(message=f"안녕하세요, {user.username}님! 보호된 페이지입니다.")


if __name__ == '__main__':
    app.run(debug=True)
