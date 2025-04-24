from flask import Flask, render_template, request, redirect, flash, session, abort, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tiny.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
db = SQLAlchemy(app)
socketio = SocketIO(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    intro = db.Column(db.Text, nullable=True)
    balance = db.Column(db.Integer, default=100000)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('products', lazy=True))
    is_hidden = db.Column(db.Boolean, default=False)

class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user1 = db.relationship("User", foreign_keys=[user1_id])
    user2 = db.relationship("User", foreign_keys=[user2_id])

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    room = db.relationship("ChatRoom", backref=db.backref("messages", lazy=True))
    sender = db.relationship("User")

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reported_product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    reporter = db.relationship("User", foreign_keys=[reporter_id])
    reported_user = db.relationship("User", foreign_keys=[reported_user_id])
    reported_product = db.relationship("Product", foreign_keys=[reported_product_id])




@app.route("/admin")
def admin_dashboard():
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect("/login")
    
    user = User.query.get(session["user_id"])
    if not user or not user.is_admin:
        flash("관리자만 접근 가능합니다.")
        return redirect("/")

    users = User.query.all()
    products = Product.query.all()
    return render_template("admin_dashboard.html", users=users, products=products)


@app.route("/admin/products")
def admin_products():
    if not session.get("user_id"):
        return redirect("/login")
    user = User.query.get(session["user_id"])
    if not user or not user.is_admin:
        abort(403)
    products = Product.query.all()
    return render_template("admin_products.html", products=products)

@app.route("/admin/users")
def admin_users():
    if not session.get("user_id"):
        return redirect("/login")
    user = User.query.get(session["user_id"])
    if not user or not user.is_admin:
        abort(403)
    users = User.query.all()
    return render_template("admin_users.html", users=users)

@app.route("/admin/reported-products")
def admin_reported_products():
    if not session.get("user_id"):
        return redirect("/login")
    user = User.query.get(session["user_id"])
    if not user or not user.is_admin:
        abort(403)
    reports = Report.query.filter(Report.reported_product_id.isnot(None)).all()
    return render_template("admin_reported_products.html", reports=reports)

@app.route("/admin/reported-users")
def admin_reported_users():
    if not session.get("user_id"):
        return redirect("/login")
    user = User.query.get(session["user_id"])
    if not user or not user.is_admin:
        abort(403)
    reports = Report.query.filter(Report.reported_user_id.isnot(None)).all()
    return render_template("admin_reported_users.html", reports=reports)



@app.route("/admin/products/<int:product_id>/toggle", methods=["POST"])
def admin_toggle_product(product_id):
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect("/login")
    
    user = User.query.get(session["user_id"])
    if not user or not user.is_admin:
        abort(403)

    product = Product.query.get_or_404(product_id)
    product.is_hidden = True  # 여기서 실제로 차단됨
    db.session.commit()
    flash("상품이 차단되었습니다.")
    return redirect("/admin/reported-products")


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
def toggle_user_active(user_id):
    if not session.get("is_admin"):
        abort(403)

    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    flash(f"유저 {user.username} 계정이 {'휴면 해제' if user.is_active else '휴면 처리'}되었습니다.")
    return redirect("/admin/reported-users")



@app.route("/admin/users/<int:user_id>/suspend", methods=["POST"])
def suspend_user(user_id):
    if not is_admin():
        abort(403)
    user = User.query.get_or_404(user_id)
    user.is_active = False
    db.session.commit()
    flash("사용자가 휴면 계정으로 전환되었습니다.")
    return redirect("/admin/reported-users")




@app.route("/", methods=["GET"])
def home():
    query = request.args.get("query", "")
    if query:
        products = Product.query.filter(Product.name.ilike(f"%{query}%")).all()
    else:
        products = Product.query.order_by(Product.created_at.desc()).all()
    return render_template("index.html", products=products)



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        intro = request.form.get("intro", "")

        if User.query.filter_by(username=username).first():
            flash("이미 존재하는 사용자명입니다.")
            return redirect("/register")

        hashed_pw = generate_password_hash(password)
        user = User(username=username, email=email, password=hashed_pw, intro=intro)
        db.session.add(user)
        db.session.commit()
        flash("회원가입이 완료되었습니다!")
        return redirect("/login")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user:
            if not user.is_active:
                flash("이 계정은 휴면 처리되어 로그인할 수 없습니다.")
                return redirect("/login")
            if check_password_hash(user.password, password):
                session["user_id"] = user.id
                session["is_admin"] = user.is_admin  # ✅ 관리자 여부 저장
                flash("로그인 성공!")

                if user.is_admin:
                    return redirect("/admin")  # ✅ 관리자라면 대시보드로
                else:
                    return redirect("/")
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        return redirect("/login")
    return render_template("login.html")



@app.route("/logout")
def logout():
    session.clear()
    flash("로그아웃 되었습니다.")
    return redirect("/")

@app.route("/mypage", methods=["GET", "POST"])
def mypage():
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect("/login")
    user = User.query.get(session["user_id"])
    if request.method == "POST":
        user.intro = request.form.get("intro", "")
        db.session.commit()
        flash("자기소개가 수정되었습니다.")
        return redirect("/mypage")
    my_products = Product.query.filter_by(user_id=user.id).order_by(Product.created_at.desc()).all()
    return render_template("mypage.html", user=user, my_products=my_products)

@app.route("/change-password", methods=["POST"])
def change_password():
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect("/login")
    user = User.query.get(session["user_id"])
    current_pw = request.form["current_password"]
    new_pw = request.form["new_password"]
    confirm_pw = request.form["confirm_password"]
    if not check_password_hash(user.password, current_pw):
        flash("현재 비밀번호가 일치하지 않습니다.")
        return redirect("/mypage")
    if new_pw != confirm_pw:
        flash("새 비밀번호가 일치하지 않습니다.")
        return redirect("/mypage")
    user.password = generate_password_hash(new_pw)
    db.session.commit()
    flash("비밀번호가 성공적으로 변경되었습니다.")
    return redirect("/mypage")

@app.route("/products/new", methods=["GET", "POST"])
def new_product():
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect("/login")

    user = User.query.get(session["user_id"])
    if not user.is_active:
        flash("휴면 계정은 상품을 등록할 수 없습니다.")
        return redirect("/")

    if request.method == "POST":
        name = request.form["name"]
        price = request.form["price"]
        file = request.files["image"]
        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
        product = Product(name=name, price=price, image=filename, user_id=user.id)
        db.session.add(product)
        db.session.commit()
        flash("상품이 등록되었습니다.")
        return redirect("/")
    return render_template("new_product.html")


@app.route("/products")
def product_list():
    query = request.args.get("query", "")
    if query:
        products = Product.query.filter(Product.name.ilike(f"%{query}%")).order_by(Product.created_at.desc()).all()
    else:
        products = Product.query.order_by(Product.created_at.desc()).all()
    return render_template("product_list.html", products=products, query=query)


@app.route("/products/<int:product_id>")
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    user = User.query.get(product.user_id)
    return render_template("product_detail.html", product=product, user=user)

@app.route("/products/<int:product_id>/delete", methods=["POST"])
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    user = User.query.get(session.get("user_id"))

    if not user:
        flash("로그인이 필요합니다.")
        return redirect("/login")

    # 어드민이거나 상품 등록자일 경우에만 삭제 허용
    if product.user_id != user.id and not getattr(user, "is_admin", False):
        abort(403)

    db.session.delete(product)
    db.session.commit()
    flash("상품이 삭제되었습니다.")
    return redirect("/mypage" if not user.is_admin else "/admin/products")


@app.route("/products/<int:product_id>/edit", methods=["GET", "POST"])
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.user_id != session.get("user_id"):
        abort(403)
    if request.method == "POST":
        product.name = request.form["name"]
        product.price = request.form["price"]
        file = request.files["image"]
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            product.image = filename
        db.session.commit()
        flash("상품이 수정되었습니다.")
        return redirect(f"/products/{product.id}")
    return render_template("edit_product.html", product=product)

@app.route("/chat")
def chat():
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect("/login")
    return render_template("chat.html")

@app.route("/chat/start/<int:product_id>")
def start_chat(product_id):
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect("/login")

    product = Product.query.get_or_404(product_id)
    user1_id = session["user_id"]
    user2_id = product.user_id

    if user1_id == user2_id:
        flash("자기 자신과는 채팅할 수 없습니다.")
        return redirect(f"/products/{product_id}")

    u1, u2 = sorted([user1_id, user2_id])
    room = ChatRoom.query.filter_by(user1_id=u1, user2_id=u2).first()

    if not room:
        room = ChatRoom(user1_id=u1, user2_id=u2)
        db.session.add(room)
        db.session.commit()

    return redirect(f"/chat/room/{room.id}")

@app.route("/chat/room/<int:room_id>")
def chat_room(room_id):
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect("/login")

    room = ChatRoom.query.get_or_404(room_id)
    if session["user_id"] not in [room.user1_id, room.user2_id]:
        abort(403)

    return render_template("chat_room.html", room=room)

@socketio.on("join")
def handle_join(data):
    room_id = data.get("room_id")
    if room_id:
        join_room(str(room_id))

@socketio.on("message")
def handle_message(data):
    # 잘못된 데이터 형식 방어
    if not isinstance(data, dict):
        print("❗ handle_message에서 잘못된 메시지 형식 수신:", data)
        return

    room_id = data.get("room_id", "global")
    content = data.get("content")
    sender_id = session.get("user_id")

    if not sender_id or not content:
        print("❗ 메시지 필수 정보 누락:", sender_id, content)
        return

    # ✅ room_id가 'global'이 아니면 DB에 저장
    if room_id != "global":
        message = ChatMessage(room_id=room_id, sender_id=sender_id, content=content)
        db.session.add(message)
        db.session.commit()

    # ✅ 브로드캐스트 방식 구분
    if room_id == "global":
        emit("message", {
            "sender_id": sender_id,
            "content": f"[전체] {content}"
        }, broadcast=True)
    else:
        emit("message", {
            "sender_id": sender_id,
            "content": content
        }, room=str(room_id))



@app.route("/report", methods=["GET", "POST"])
def report():
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect("/login")

    user_id = request.args.get("user_id")
    product_id = request.args.get("product_id")

    if request.method == "POST":
        reason = request.form.get("reason")
        try:
            report = Report(
                reporter_id=session["user_id"],
                reported_user_id=int(user_id) if user_id else None,
                reported_product_id=int(product_id) if product_id else None,
                reason=reason
            )
            db.session.add(report)
            db.session.commit()

            if product_id:
                count = Report.query.filter_by(reported_product_id=int(product_id)).count()
                if count >= 3:
                    product = Product.query.get(int(product_id))
                    if product:
                        product.is_hidden = True
                        db.session.commit()

            if user_id:
                count = Report.query.filter_by(reported_user_id=int(user_id)).count()
                if count >= 5:
                    user = User.query.get(int(user_id))
                    if user:
                        user.is_active = False
                        db.session.commit()

            flash("신고가 접수되었습니다.")
            return redirect("/")

        except Exception as e:
            db.session.rollback()
            flash(f"신고 처리 중 오류가 발생했습니다: {str(e)}")
            return redirect("/")

    return render_template("report.html", user_id=user_id, product_id=product_id)

@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect("/login")

    current_user = User.query.get(session["user_id"])
    users = User.query.filter(User.id != current_user.id).all()

    if request.method == "POST":
        try:
            recipient_id = int(request.form["recipient_id"])
            amount = int(request.form["amount"])

            recipient = User.query.get(recipient_id)

            if not recipient:
                flash("수신 유저가 존재하지 않습니다.")
            elif amount <= 0:
                flash("송금 금액은 0원 이상이어야 합니다.")
            elif current_user.balance < amount:
                flash("잔액이 부족합니다.")
            else:
                current_user.balance -= amount
                recipient.balance += amount
                db.session.commit()
                flash(f"{recipient.username}에게 {amount:,}원을 송금했습니다.")
                return redirect("/mypage")

        except Exception as e:
            db.session.rollback()
            flash(f"송금 처리 중 오류가 발생했습니다: {str(e)}")

    return render_template("transfer.html", users=users, balance=current_user.balance)



if __name__ == '__main__':
    socketio.run(app, debug=True)
