from flask import Flask, render_template, session, redirect, url_for, request

import random
import razorpay
import bcrypt

from database import debug
from mail import send_email
import os
from dotenv import load_dotenv

load_dotenv()


app = Flask(__name__)

# Secret key for sessions
app.secret_key = os.getenv("FLASK_SECRET_KEY")


# =========================================================
# RAZORPAY
# =========================================================

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

razorpay_client = razorpay.Client(
    auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)
)


# =========================================================
# OTP
# =========================================================

def generate_otp():
    return str(random.randint(100000, 999999))


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    return render_template("home.html")


# =========================================================
# AUTHENTICATION
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        connection = debug()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT * FROM users WHERE email = %s",
            (email,)
        )

        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if user is None:
            return render_template(
                "login.html",
                error="Invalid email or password."
            )

        if bcrypt.checkpw(
            password.encode("utf-8"),
            user["password"].encode("utf-8")
        ):

            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]

            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid email or password."
        )

    return render_template("login.html")


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form["name"]
        email = request.form["email"]
        phone = request.form["phone"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:

            return render_template(
                "register.html",
                error="Passwords do not match."
            )

        connection = debug()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT id FROM users WHERE email = %s OR phone = %s",
            (email, phone)
        )

        existing_user = cursor.fetchone()

        if existing_user:

            cursor.close()
            connection.close()

            return render_template(
                "register.html",
                error="Email or phone number is already registered."
            )

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        cursor.execute(
            """
            INSERT INTO users
            (name, email, phone, password)
            VALUES (%s, %s, %s, %s)
            """,
            (
                name,
                email,
                phone,
                hashed_password.decode("utf-8")
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for("login"))

    return render_template("register.html")


# =========================================================
# FORGOT PASSWORD
# =========================================================

@app.route("/forgotpassword", methods=["GET", "POST"])
def forgotpassword():

    if request.method == "POST":

        email = request.form["email"]

        connection = debug()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT id FROM users WHERE email = %s",
            (email,)
        )

        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if user is None:

            return render_template(
                "forgotpassword.html",
                error="No account found with this email."
            )

        otp = generate_otp()

        session["reset_email"] = email
        session["reset_otp"] = otp

        try:

            send_email(email, otp)

        except Exception:

            return render_template(
                "forgotpassword.html",
                error="Unable to send OTP. Please try again."
            )

        return redirect(url_for("resetpassword"))

    return render_template("forgotpassword.html")


# =========================================================
# RESET PASSWORD
# =========================================================

@app.route("/resetpassword", methods=["GET", "POST"])
def resetpassword():

    if request.method == "POST":

        otp = request.form["otp"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        saved_otp = session.get("reset_otp")
        email = session.get("reset_email")

        if saved_otp is None or email is None:

            return render_template(
                "resetpassword.html",
                error="Password reset session expired. Please try again."
            )

        if otp != saved_otp:

            return render_template(
                "resetpassword.html",
                error="Invalid OTP."
            )

        if password != confirm_password:

            return render_template(
                "resetpassword.html",
                error="Passwords do not match."
            )

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        connection = debug()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE users
            SET password = %s
            WHERE email = %s
            """,
            (
                hashed_password.decode("utf-8"),
                email
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        session.pop("reset_otp", None)
        session.pop("reset_email", None)

        return redirect(url_for("login"))

    return render_template("resetpassword.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("home"))


# =========================================================
# USER
# =========================================================

@app.route("/dashboard")
def dashboard():

    # User must be logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Connect to VEZORA database
    connection = debug()
    cursor = connection.cursor(dictionary=True)

    # Get available products
    cursor.execute(
        """
        SELECT
            id,
            name,
            category,
            description,
            price,
            stock,
            image,
            rating
        FROM products
        WHERE stock > 0
        ORDER BY id DESC
        """
    )

    products = cursor.fetchall()

    # Get products added to favorites by the logged-in user
    cursor.execute(
        """
        SELECT product_id
        FROM favourites
        WHERE user_id = %s
        """,
        (session["user_id"],)
    )

    favorites = cursor.fetchall()

    # Store favorite product IDs
    favorite_ids = {
        item["product_id"]
        for item in favorites
    }

    # Mark each product as favorite or not
    for product in products:
        product["is_favorite"] = (
            product["id"] in favorite_ids
        )

    cursor.close()
    connection.close()

    return render_template(
        "dashboard.html",
        products=products
    )


@app.route("/profile", methods=["GET", "POST"])
def profile():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    if request.method == "POST":

        name = request.form["name"]
        phone = request.form["phone"]

        cursor.execute(
            """
            SELECT id
            FROM users
            WHERE phone = %s
            AND id != %s
            """,
            (phone, session["user_id"])
        )

        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            connection.close()

            return render_template(
                "profile.html",
                user={
                    "name": name,
                    "email": session["user_email"],
                    "phone": phone
                },
                error="Phone number is already registered."
            )

        cursor.execute(
            """
            UPDATE users
            SET name = %s,
                phone = %s
            WHERE id = %s
            """,
            (
                name,
                phone,
                session["user_id"]
            )
        )

        connection.commit()

        session["user_name"] = name

        cursor.close()
        connection.close()

        return redirect(url_for("profile"))

    cursor.execute(
        """
        SELECT
            id,
            name,
            email,
            phone,
            created_at
        FROM users
        WHERE id = %s
        """,
        (session["user_id"],)
    )

    user = cursor.fetchone()

    cursor.close()
    connection.close()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    return render_template(
        "profile.html",
        user=user
    )


# =========================================================
# PRODUCTS
# =========================================================

@app.route("/products")
def products():

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            id,
            name,
            category,
            description,
            price,
            stock,
            image,
            rating
        FROM products
        WHERE stock > 0
        ORDER BY id DESC
        """
    )

    products = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "products.html",
        products=products
    )


@app.route("/product/<int:product_id>")
def productdetails(product_id):

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            id,
            name,
            category,
            description,
            price,
            stock,
            image,
            rating
        FROM products
        WHERE id = %s
        """,
        (product_id,)
    )

    product = cursor.fetchone()

    if product is None:
        cursor.close()
        connection.close()
        return render_template("404.html"), 404

    product["is_favorite"] = False

    if session.get("user_id"):

        cursor.execute(
            """
            SELECT id
            FROM favourites
            WHERE user_id = %s
            AND product_id = %s
            """,
            (session["user_id"], product_id)
        )

        favorite = cursor.fetchone()

        if favorite:
            product["is_favorite"] = True

    cursor.close()
    connection.close()

    return render_template(
        "productdetails.html",
        product=product
    )


@app.route("/categories")
def categories():
    return render_template("categories.html")


@app.route("/category/<category_name>")
def category(category_name):

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            id,
            name,
            category,
            description,
            price,
            stock,
            image,
            rating
        FROM products
        WHERE category = %s
        AND stock > 0
        ORDER BY id DESC
        """,
        (category_name,)
    )

    products = cursor.fetchall()

    if session.get("user_id"):

        cursor.execute(
            """
            SELECT product_id
            FROM favourites
            WHERE user_id = %s
            """,
            (session["user_id"],)
        )

        favorites = cursor.fetchall()

        favorite_ids = {
            item["product_id"]
            for item in favorites
        }

    else:
        favorite_ids = set()

    for product in products:
        product["is_favorite"] = (
            product["id"] in favorite_ids
        )

    cursor.close()
    connection.close()

    return render_template(
        "category.html",
        products=products,
        category_name=category_name
    )





# =========================================================
# CART
# =========================================================

@app.route("/mycart")
def mycart():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            cart.id AS cart_id,
            cart.product_id,
            cart.quantity,
            products.name,
            products.category,
            products.description,
            products.price,
            products.stock,
            products.image,
            products.rating
        FROM cart
        INNER JOIN products
            ON cart.product_id = products.id
        WHERE cart.user_id = %s
        ORDER BY cart.created_at DESC
        """,
        (session["user_id"],)
    )

    cart_items = cursor.fetchall()

    cursor.close()
    connection.close()

    subtotal = 0

    for item in cart_items:
        item["item_total"] = item["price"] * item["quantity"]
        subtotal += item["item_total"]

    return render_template(
        "mycart.html",
        cart_items=cart_items,
        subtotal=subtotal,
        total=subtotal
    )


@app.route("/addtocart/<int:product_id>")
def addtocart(product_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT id, stock
        FROM products
        WHERE id = %s
        """,
        (product_id,)
    )

    product = cursor.fetchone()

    if product is None:
        cursor.close()
        connection.close()
        return render_template("404.html"), 404

    if product["stock"] <= 0:
        cursor.close()
        connection.close()
        return redirect(request.referrer or url_for("products"))

    cursor.execute(
        """
        SELECT id, quantity
        FROM cart
        WHERE user_id = %s
        AND product_id = %s
        """,
        (session["user_id"], product_id)
    )

    existing_item = cursor.fetchone()

    if existing_item:

        if existing_item["quantity"] < product["stock"]:

            cursor.execute(
                """
                UPDATE cart
                SET quantity = quantity + 1
                WHERE id = %s
                """,
                (existing_item["id"],)
            )

    else:

        cursor.execute(
            """
            INSERT INTO cart
            (user_id, product_id, quantity)
            VALUES (%s, %s, 1)
            """,
            (session["user_id"], product_id)
        )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("mycart"))


@app.route("/removefromcart/<int:product_id>")
def removefromcart(product_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM cart
        WHERE user_id = %s
        AND product_id = %s
        """,
        (session["user_id"], product_id)
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("mycart"))


@app.route("/updatecart/<int:product_id>/<action>")
def updatecart(product_id, action):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            cart.id,
            cart.quantity,
            products.stock
        FROM cart
        INNER JOIN products
            ON cart.product_id = products.id
        WHERE cart.user_id = %s
        AND cart.product_id = %s
        """,
        (session["user_id"], product_id)
    )

    item = cursor.fetchone()

    if item is None:
        cursor.close()
        connection.close()
        return redirect(url_for("mycart"))

    if action == "increase":

        if item["quantity"] < item["stock"]:

            cursor.execute(
                """
                UPDATE cart
                SET quantity = quantity + 1
                WHERE id = %s
                """,
                (item["id"],)
            )

    elif action == "decrease":

        if item["quantity"] > 1:

            cursor.execute(
                """
                UPDATE cart
                SET quantity = quantity - 1
                WHERE id = %s
                """,
                (item["id"],)
            )

        else:

            cursor.execute(
                """
                DELETE FROM cart
                WHERE id = %s
                """,
                (item["id"],)
            )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("mycart"))


# =========================================================
# FAVORITES / WISHLIST
# =========================================================

@app.route("/myfav")
def myfav():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            products.id,
            products.name,
            products.category,
            products.description,
            products.price,
            products.stock,
            products.image,
            products.rating
        FROM favourites
        INNER JOIN products
            ON favourites.product_id = products.id
        WHERE favourites.user_id = %s
        ORDER BY favourites.created_at DESC
        """,
        (session["user_id"],)
    )

    products = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "myfav.html",
        products=products
    )


@app.route("/addtofav/<int:product_id>")
def addtofav(product_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT IGNORE INTO favourites
        (user_id, product_id)
        VALUES (%s, %s)
        """,
        (session["user_id"], product_id)
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(request.referrer or url_for("myfav"))


@app.route("/removefromfav/<int:product_id>")
def removefromfav(product_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM favourites
        WHERE user_id = %s
        AND product_id = %s
        """,
        (session["user_id"], product_id)
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(request.referrer or url_for("myfav"))


# =========================================================
# CHECKOUT
# =========================================================

@app.route("/checkout", methods=["GET", "POST"])
def checkout():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    # Get cart items
    cursor.execute(
        """
        SELECT
            cart.product_id,
            cart.quantity,
            products.name,
            products.price,
            products.image,
            products.stock
        FROM cart
        INNER JOIN products
            ON cart.product_id = products.id
        WHERE cart.user_id = %s
        ORDER BY cart.created_at DESC
        """,
        (session["user_id"],)
    )

    cart_items = cursor.fetchall()

    if not cart_items:
        cursor.close()
        connection.close()
        return redirect(url_for("mycart"))

    # Calculate subtotal
    subtotal = 0

    for item in cart_items:
        item["item_total"] = item["price"] * item["quantity"]
        subtotal += item["item_total"]

    # Get saved addresses
    cursor.execute(
        """
        SELECT
            id,
            full_name,
            phone,
            address_line,
            city,
            state,
            pincode,
            is_default,
            address_type
        FROM address
        WHERE user_id = %s
        ORDER BY is_default DESC, id DESC
        """,
        (session["user_id"],)
    )

    addresses = cursor.fetchall()

    cursor.close()
    connection.close()

    if request.method == "POST":

        address_id = request.form.get("address_id")

        if not address_id:
            return render_template(
                "checkout.html",
                cart_items=cart_items,
                addresses=addresses,
                subtotal=subtotal,
                total=subtotal,
                error="Please select a delivery address."
            )

        connection = debug()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id
            FROM address
            WHERE id = %s
            AND user_id = %s
            """,
            (address_id, session["user_id"])
        )

        selected_address = cursor.fetchone()

        cursor.close()
        connection.close()

        if selected_address is None:
            return render_template(
                "checkout.html",
                cart_items=cart_items,
                addresses=addresses,
                subtotal=subtotal,
                total=subtotal,
                error="Invalid delivery address."
            )

        session["checkout_address_id"] = int(address_id)

        return redirect(url_for("ordersummary"))

    return render_template(
        "checkout.html",
        cart_items=cart_items,
        addresses=addresses,
        subtotal=subtotal,
        total=subtotal
    )


@app.route("/address")
def address():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            id,
            full_name,
            phone,
            address_line,
            city,
            state,
            pincode,
            is_default,
            address_type
        FROM address
        WHERE user_id = %s
        ORDER BY is_default DESC, id DESC
        """,
        (session["user_id"],)
    )

    addresses = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "address.html",
        addresses=addresses
    )


@app.route("/addaddress", methods=["GET", "POST"])
def addaddress():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        full_name = request.form["full_name"]
        phone = request.form["phone"]
        address_line = request.form["address_line"]
        city = request.form["city"]
        state = request.form["state"]
        pincode = request.form["pincode"]
        address_type = request.form["address_type"]
        is_default = request.form.get("is_default") == "on"

        connection = debug()
        cursor = connection.cursor()

        if is_default:

            cursor.execute(
                """
                UPDATE address
                SET is_default = FALSE
                WHERE user_id = %s
                """,
                (session["user_id"],)
            )

        cursor.execute(
            """
            SELECT id
            FROM address
            WHERE user_id = %s
            """,
            (session["user_id"],)
        )

        existing_address = cursor.fetchone()

        if existing_address is None:
            is_default = True

        cursor.execute(
            """
            INSERT INTO address
            (
                user_id,
                full_name,
                phone,
                address_line,
                city,
                state,
                pincode,
                is_default,
                address_type
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                session["user_id"],
                full_name,
                phone,
                address_line,
                city,
                state,
                pincode,
                is_default,
                address_type
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for("address"))

    return render_template("addaddress.html")


@app.route("/setdefaultaddress/<int:address_id>")
def setdefaultaddress(address_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE address
        SET is_default = FALSE
        WHERE user_id = %s
        """,
        (session["user_id"],)
    )

    cursor.execute(
        """
        UPDATE address
        SET is_default = TRUE
        WHERE id = %s
        AND user_id = %s
        """,
        (address_id, session["user_id"])
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("address"))


@app.route("/deleteaddress/<int:address_id>")
def deleteaddress(address_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT is_default
        FROM address
        WHERE id = %s
        AND user_id = %s
        """,
        (address_id, session["user_id"])
    )

    selected_address = cursor.fetchone()

    if selected_address is None:
        cursor.close()
        connection.close()
        return redirect(url_for("address"))

    cursor.execute(
        """
        DELETE FROM address
        WHERE id = %s
        AND user_id = %s
        """,
        (address_id, session["user_id"])
    )

    if selected_address["is_default"]:

        cursor.execute(
            """
            SELECT id
            FROM address
            WHERE user_id = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (session["user_id"],)
        )

        next_address = cursor.fetchone()

        if next_address:

            cursor.execute(
                """
                UPDATE address
                SET is_default = TRUE
                WHERE id = %s
                """,
                (next_address["id"],)
            )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("address"))


# =========================================================
# ORDER
# =========================================================

@app.route("/ordersummary", methods=["GET", "POST"])
def ordersummary():

    if "user_id" not in session:
        return redirect(url_for("login"))

    address_id = session.get("checkout_address_id")

    if not address_id:
        return redirect(url_for("checkout"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    # Get selected address
    cursor.execute(
        """
        SELECT
            id,
            full_name,
            phone,
            address_line,
            city,
            state,
            pincode,
            address_type
        FROM address
        WHERE id = %s
        AND user_id = %s
        """,
        (address_id, session["user_id"])
    )

    address = cursor.fetchone()

    if address is None:
        cursor.close()
        connection.close()
        session.pop("checkout_address_id", None)
        return redirect(url_for("checkout"))

    # Get cart items
    cursor.execute(
        """
        SELECT
            cart.product_id,
            cart.quantity,
            products.name,
            products.category,
            products.price,
            products.image,
            products.stock
        FROM cart
        INNER JOIN products
            ON cart.product_id = products.id
        WHERE cart.user_id = %s
        ORDER BY cart.created_at DESC
        """,
        (session["user_id"],)
    )

    cart_items = cursor.fetchall()

    if not cart_items:
        cursor.close()
        connection.close()
        return redirect(url_for("mycart"))

    subtotal = 0

    for item in cart_items:
        item["item_total"] = item["price"] * item["quantity"]
        subtotal += item["item_total"]

    cursor.close()
    connection.close()

    total = subtotal

    # Continue to payment
    if request.method == "POST":

        session["order_total"] = float(total)

        return redirect(url_for("payment"))

    return render_template(
        "ordersummary.html",
        address=address,
        cart_items=cart_items,
        subtotal=subtotal,
        total=total
    )


@app.route("/myorders")
def myorders():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            orders.id,
            orders.total_amount,
            orders.status,
            orders.payment_status,
            orders.created_at,
            payments.payment_method
        FROM orders
        LEFT JOIN payments
            ON orders.id = payments.order_id
        WHERE orders.user_id = %s
        ORDER BY orders.created_at DESC
        """,
        (session["user_id"],)
    )

    orders = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "myorders.html",
        orders=orders
    )


@app.route("/orderdetails/<int:order_id>")
def orderdetails(order_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    # Get order details
    cursor.execute(
        """
        SELECT
            orders.id,
            orders.total_amount,
            orders.status,
            orders.payment_status,
            orders.created_at,
            payments.payment_method,
            payments.transaction_id
        FROM orders
        LEFT JOIN payments
            ON orders.id = payments.order_id
        WHERE orders.id = %s
        AND orders.user_id = %s
        """,
        (order_id, session["user_id"])
    )

    order = cursor.fetchone()

    if order is None:
        cursor.close()
        connection.close()
        return render_template("404.html"), 404

    # Get delivery address
    cursor.execute(
        """
        SELECT
            full_name,
            phone,
            address_line,
            city,
            state,
            pincode,
            address_type
        FROM address
        INNER JOIN orders
            ON address.id = orders.address_id
        WHERE orders.id = %s
        AND orders.user_id = %s
        """,
        (order_id, session["user_id"])
    )

    address = cursor.fetchone()

    # Get ordered products
    cursor.execute(
        """
        SELECT
            order_items.product_id,
            order_items.quantity,
            order_items.price,
            products.name,
            products.category,
            products.image
        FROM order_items
        INNER JOIN products
            ON order_items.product_id = products.id
        WHERE order_items.order_id = %s
        ORDER BY order_items.id
        """,
        (order_id,)
    )

    order_items = cursor.fetchall()

    cursor.close()
    connection.close()

    for item in order_items:
        item["item_total"] = item["price"] * item["quantity"]

    return render_template(
        "orderdetails.html",
        order=order,
        address=address,
        order_items=order_items
    )


# =========================================================
# ORDER TRACKING
# =========================================================

@app.route("/track/<int:order_id>")
def track(order_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            orders.id,
            orders.total_amount,
            orders.status,
            orders.payment_status,
            orders.created_at,
            payments.payment_method
        FROM orders
        LEFT JOIN payments
            ON orders.id = payments.order_id
        WHERE orders.id = %s
        AND orders.user_id = %s
        """,
        (order_id, session["user_id"])
    )

    order = cursor.fetchone()

    cursor.close()
    connection.close()

    if order is None:
        return render_template("404.html"), 404

    status_order = [
        "Placed",
        "Confirmed",
        "Shipped",
        "Out for Delivery",
        "Delivered"
    ]

    if order["status"] in status_order:
        current_index = status_order.index(order["status"])
    else:
        current_index = -1

    return render_template(
        "track.html",
        order=order,
        status_order=status_order,
        current_index=current_index
    )



# =========================================================
# PAYMENT
# =========================================================

@app.route("/payment", methods=["GET", "POST"])
def payment():

    if "user_id" not in session:
        return redirect(url_for("login"))

    address_id = session.get("checkout_address_id")
    order_total = session.get("order_total")

    if not address_id or order_total is None:
        return redirect(url_for("checkout"))

    if request.method == "POST":

        payment_method = request.form.get("payment_method")

        if payment_method not in [
            "UPI",
            "Credit Card",
            "Debit Card",
            "Net Banking",
            "Cash on Delivery"
        ]:
            return render_template(
                "payment.html",
                order_total=order_total,
                error="Please select a valid payment method."
            )

        session["payment_method"] = payment_method

        # Cash on Delivery
        if payment_method == "Cash on Delivery":
            return redirect(url_for("place_cod_order"))

        # Online payment through Razorpay
        return redirect(url_for("create_razorpay_order"))

    return render_template(
        "payment.html",
        order_total=order_total
    )


# =========================================================
# CREATE RAZORPAY ORDER
# =========================================================

@app.route("/create_razorpay_order")
def create_razorpay_order():

    if "user_id" not in session:
        return redirect(url_for("login"))

    order_total = session.get("order_total")
    payment_method = session.get("payment_method")

    if order_total is None:
        return redirect(url_for("checkout"))

    if payment_method not in [
        "UPI",
        "Credit Card",
        "Debit Card",
        "Net Banking"
    ]:
        return redirect(url_for("payment"))

    try:

        amount = int(float(order_total) * 100)

        razorpay_order = razorpay_client.order.create({
            "amount": amount,
            "currency": "INR",
            "receipt": "VEZORA_" + str(session["user_id"])
        })

        session["razorpay_order_id"] = razorpay_order["id"]

        return render_template(
            "razorpay.html",
            razorpay_key=RAZORPAY_KEY_ID,
            razorpay_order_id=razorpay_order["id"],
            amount=amount,
            order_total=order_total,
            payment_method=payment_method,
            user_name=session.get("user_name"),
            user_email=session.get("user_email")
        )

    except Exception as e:

        print("====================================")
        print("RAZORPAY ERROR:", e)
        print("====================================")

        return f"Razorpay Error: {e}"


# =========================================================
# PLACE COD ORDER
# =========================================================

@app.route("/placecodorder")
def place_cod_order():

    if "user_id" not in session:
        return redirect(url_for("login"))

    address_id = session.get("checkout_address_id")

    if not address_id:
        return redirect(url_for("checkout"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    try:

        # -------------------------------------------------
        # Check address
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT id
            FROM address
            WHERE id = %s
            AND user_id = %s
            """,
            (
                address_id,
                session["user_id"]
            )
        )

        address = cursor.fetchone()

        if address is None:
            connection.rollback()
            return redirect(url_for("checkout"))

        # -------------------------------------------------
        # Get cart items
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                cart.product_id,
                cart.quantity,
                products.price,
                products.stock
            FROM cart
            INNER JOIN products
                ON cart.product_id = products.id
            WHERE cart.user_id = %s
            """,
            (session["user_id"],)
        )

        cart_items = cursor.fetchall()

        if not cart_items:
            connection.rollback()
            return redirect(url_for("mycart"))

        # -------------------------------------------------
        # Check stock and calculate total
        # -------------------------------------------------

        total = 0

        for item in cart_items:

            if item["quantity"] > item["stock"]:
                connection.rollback()
                return redirect(url_for("mycart"))

            total += item["price"] * item["quantity"]

        # -------------------------------------------------
        # Create order
        # -------------------------------------------------

        cursor.execute(
            """
            INSERT INTO orders
            (
                user_id,
                address_id,
                total_amount,
                status,
                payment_status
            )
            VALUES
            (%s, %s, %s, 'Placed', 'Pending')
            """,
            (
                session["user_id"],
                address_id,
                total
            )
        )

        order_id = cursor.lastrowid

        # -------------------------------------------------
        # Add order items and reduce stock
        # -------------------------------------------------

        for item in cart_items:

            cursor.execute(
                """
                INSERT INTO order_items
                (
                    order_id,
                    product_id,
                    quantity,
                    price
                )
                VALUES
                (%s, %s, %s, %s)
                """,
                (
                    order_id,
                    item["product_id"],
                    item["quantity"],
                    item["price"]
                )
            )

            cursor.execute(
                """
                UPDATE products
                SET stock = stock - %s
                WHERE id = %s
                """,
                (
                    item["quantity"],
                    item["product_id"]
                )
            )

        # -------------------------------------------------
        # Create payment record
        # -------------------------------------------------

        cursor.execute(
            """
            INSERT INTO payments
            (
                order_id,
                payment_method,
                amount,
                payment_status
            )
            VALUES
            (%s, 'Cash on Delivery', %s, 'Pending')
            """,
            (
                order_id,
                total
            )
        )

        # -------------------------------------------------
        # Clear cart
        # -------------------------------------------------

        cursor.execute(
            """
            DELETE FROM cart
            WHERE user_id = %s
            """,
            (session["user_id"],)
        )

        connection.commit()

        # -------------------------------------------------
        # Store order information
        # -------------------------------------------------

        session["last_order_id"] = order_id
        session["last_order_total"] = float(total)
        session["last_payment_method"] = "Cash on Delivery"

        # -------------------------------------------------
        # Clear checkout information
        # -------------------------------------------------

        session.pop("checkout_address_id", None)
        session.pop("order_total", None)
        session.pop("payment_method", None)

        return redirect(url_for("paymentsuccess"))

    except Exception as e:

        connection.rollback()

        print("====================================")
        print("COD ORDER ERROR:", e)
        print("====================================")

        return render_template(
            "payment.html",
            order_total=session.get("order_total", 0),
            error="Unable to place your order. Please try again."
        )

    finally:

        cursor.close()
        connection.close()


# =========================================================
# PAYMENT SUCCESS
# =========================================================

@app.route("/paymentsuccess")
def paymentsuccess():

    if "user_id" not in session:
        return redirect(url_for("login"))

    order_id = session.get("last_order_id")
    order_total = session.get("last_order_total")

    payment_method = session.get(
        "last_payment_method",
        "Cash on Delivery"
    )

    if not order_id:
        return redirect(url_for("dashboard"))

    return render_template(
        "paymentsuccess.html",
        order_id=order_id,
        order_total=order_total,
        payment_method=payment_method
    )


# =========================================================
# PAYMENT FAILURE
# =========================================================

@app.route("/paymentfailure")
def paymentfailure():

    if "user_id" not in session:
        return redirect(url_for("login"))

    error_message = session.get(
        "payment_error",
        "Your payment could not be completed."
    )

    session.pop("payment_error", None)

    return render_template(
        "paymentfailure.html",
        error_message=error_message
    )


# =========================================================
# RAZORPAY PAYMENT SUCCESS
# =========================================================

@app.route("/payment_success", methods=["POST"])
def payment_success():

    if "user_id" not in session:
        return redirect(url_for("login"))

    address_id = session.get("checkout_address_id")
    razorpay_order_id = request.form.get("razorpay_order_id")
    razorpay_payment_id = request.form.get("razorpay_payment_id")
    razorpay_signature = request.form.get("razorpay_signature")
    payment_method = session.get("payment_method")
    order_total = session.get("order_total")

    if not address_id or order_total is None:
        return redirect(url_for("checkout"))

    if not razorpay_order_id or not razorpay_payment_id:
        return redirect(url_for("paymentfailure"))

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    try:

        # -------------------------------------------------
        # Verify Razorpay payment
        # -------------------------------------------------

        razorpay_client.utility.verify_payment_signature({
            "razorpay_order_id": razorpay_order_id,
            "razorpay_payment_id": razorpay_payment_id,
            "razorpay_signature": razorpay_signature
        })

        # -------------------------------------------------
        # Check delivery address
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT id
            FROM address
            WHERE id = %s
            AND user_id = %s
            """,
            (
                address_id,
                session["user_id"]
            )
        )

        address = cursor.fetchone()

        if address is None:
            connection.rollback()
            return redirect(url_for("checkout"))

        # -------------------------------------------------
        # Get cart items
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                cart.product_id,
                cart.quantity,
                products.price,
                products.stock
            FROM cart
            INNER JOIN products
                ON cart.product_id = products.id
            WHERE cart.user_id = %s
            """,
            (session["user_id"],)
        )

        cart_items = cursor.fetchall()

        if not cart_items:
            connection.rollback()
            return redirect(url_for("mycart"))

        # -------------------------------------------------
        # Calculate total and check stock
        # -------------------------------------------------

        total = 0

        for item in cart_items:

            if item["quantity"] > item["stock"]:
                connection.rollback()
                return redirect(url_for("mycart"))

            total += item["price"] * item["quantity"]

        # -------------------------------------------------
        # Create order
        # -------------------------------------------------

        cursor.execute(
            """
            INSERT INTO orders
            (
                user_id,
                address_id,
                total_amount,
                status,
                payment_status
            )
            VALUES
            (%s, %s, %s, 'Placed', 'Paid')
            """,
            (
                session["user_id"],
                address_id,
                total
            )
        )

        order_id = cursor.lastrowid

        # -------------------------------------------------
        # Add order items and reduce stock
        # -------------------------------------------------

        for item in cart_items:

            cursor.execute(
                """
                INSERT INTO order_items
                (
                    order_id,
                    product_id,
                    quantity,
                    price
                )
                VALUES
                (%s, %s, %s, %s)
                """,
                (
                    order_id,
                    item["product_id"],
                    item["quantity"],
                    item["price"]
                )
            )

            cursor.execute(
                """
                UPDATE products
                SET stock = stock - %s
                WHERE id = %s
                """,
                (
                    item["quantity"],
                    item["product_id"]
                )
            )

        # -------------------------------------------------
        # Save payment
        # -------------------------------------------------

        cursor.execute(
            """
            INSERT INTO payments
            (
                order_id,
                payment_method,
                transaction_id,
                amount,
                payment_status,
                payment_date
            )
            VALUES
            (%s, %s, %s, %s, 'Paid', NOW())
            """,
            (
                order_id,
                payment_method,
                razorpay_payment_id,
                total
            )
        )

        # -------------------------------------------------
        # Clear cart
        # -------------------------------------------------

        cursor.execute(
            """
            DELETE FROM cart
            WHERE user_id = %s
            """,
            (session["user_id"],)
        )

        connection.commit()

        # -------------------------------------------------
        # Store success information
        # -------------------------------------------------

        session["last_order_id"] = order_id
        session["last_order_total"] = float(total)
        session["last_payment_method"] = payment_method

        # -------------------------------------------------
        # Clear checkout information
        # -------------------------------------------------

        session.pop("checkout_address_id", None)
        session.pop("order_total", None)
        session.pop("payment_method", None)
        session.pop("razorpay_order_id", None)

        return redirect(url_for("paymentsuccess"))

    except Exception as e:

        connection.rollback()

        print("====================================")
        print("RAZORPAY PAYMENT ERROR:", e)
        print("====================================")

        session["payment_error"] = (
            "Payment verification failed. Please try again."
        )

        return redirect(url_for("paymentfailure"))

    finally:

        cursor.close()
        connection.close()


# =========================================================
# OFFERS AND COUPONS
# =========================================================

@app.route("/offers")
def offers():

    return render_template("offers.html")


@app.route("/coupons")
def coupons():

    return render_template("coupons.html")
# =========================================================
# REVIEWS
# =========================================================

@app.route("/reviews/<int:product_id>")
def reviews(product_id):
    return render_template(
        "reviews.html",
        product_id=product_id
    )


@app.route("/write-review/<int:product_id>")
def write_review(product_id):
    return render_template(
        "write_review.html",
        product_id=product_id
    )


# =========================================================
# SUPPORT
# =========================================================

@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/faq")
def faq():
    return render_template("faq.html")


# =========================================================
# ABOUT
# =========================================================

@app.route("/about")
def about():
    return render_template("about.html")


# =========================================================
# 404 ERROR
# =========================================================

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404

@app.route("/search")
def search():

    query = request.args.get("q", "").strip()

    connection = debug()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            id,
            name,
            category,
            description,
            price,
            stock,
            image,
            rating
        FROM products
        WHERE name LIKE %s
        OR category LIKE %s
        ORDER BY id DESC
        """,
        (f"%{query}%", f"%{query}%")
    )

    products = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "search.html",
        products=products,
        query=query
    )
# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)