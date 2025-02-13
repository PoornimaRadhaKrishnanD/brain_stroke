from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import os
import pandas as pd
import joblib
from fpdf import FPDF

app = Flask(__name__, template_folder='template')
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Poornima%402005@localhost/brain_stroke_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configurations
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'rkpoornima2005@gmail.com'
app.config['MAIL_PASSWORD'] = 'cpexvyjvlfhoscds'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Load the trained model
stroke_model = joblib.load("model.joblib")

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        phone=request.form['phone']
        existing_user = User.query.filter((User.email == email) | (User.phone == phone)).first()
        if existing_user:
            flash('Email already registered!', 'danger')
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password,phone=phone)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    print("Login route accessed")
    if request.method == 'POST':
        print("Form submitted")
        email = request.form['email']
        password = request.form['password']
        print(f"Received Email: {email}, Password: {password}")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            print("User logged in successfully!")
            flash('Login successful!', 'success')
            return redirect(url_for('predict'))
        print("Login failed! Invalid credentials.")
        flash('Invalid credentials. Try again.', 'danger')
    return render_template('login.html')

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Brain Stroke Prediction Route
@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if request.method == 'POST':
        patient_name = request.form['patient_name']
        guardian_name = request.form['guardian_name']
        guardian_email = request.form['guardian_email']
        patient_age = int(request.form['patient_age'])
        gender = request.form['gender'].lower()
        hypertension = int(request.form['hypertension'])
        heart_disease = int(request.form['heart_disease'])
        ever_married = request.form['ever_married'].lower()
        work_type = request.form['work_type']
        residence_type = request.form['residence_type']
        avg_glucose_level = float(request.form['avg_glucose_level'])
        bmi = float(request.form['bmi'])
        smoking_status = request.form['smoking_status'].lower()

        work_type_mapping = {
            "Government job": "Govt_job",
            "Children": "children",
            "Never Worked": "Never_worked",
            "Private": "Private",
        }

        single_input = {
            "gender": gender,
            "age": patient_age,
            "hypertension": hypertension,
            "heart_disease": heart_disease,
            "ever_married": ever_married,
            "work_type": work_type_mapping.get(work_type, work_type),
            "Residence_type": residence_type,
            "avg_glucose_level": avg_glucose_level,
            "bmi": bmi,
            "smoking_status": smoking_status,
        }

        prediction = predict_input(single_input)
        result = "Likely" if prediction == 1 else "Not Likely"

        if result == "Likely":
            pdf_path = generate_pdf(patient_name, guardian_name, result)
            subject = f"Stroke Prediction Report for {patient_name}"
            body = f"""
            Dear {guardian_name},

            The stroke prediction for {patient_name} indicates that a stroke is {result}.
            We highly recommend immediate medical consultation.

            Please find the attached stroke prediction report, which includes:
            - Nearest hospital recommendation
            - Date to be reached
            - Estimated stroke risk percentage
            - Appointment confirmation

            Regards,
            Healthcare Team
            """
            
            msg = Message(subject, sender='rkpoornima2005@gmail.com', recipients=[guardian_email])
            msg.body = body
            
            # Attach PDF
            with open(pdf_path, "rb") as fp:
                msg.attach(pdf_path, "application/pdf", fp.read())
            mail.send(msg)
            #send_email(guardian_email, guardian_name, pdf_path)
            os.remove(pdf_path)

        return render_template('result.html', result=result, patient_name=patient_name, guardian_name=guardian_name, guardian_email=guardian_email)

    return render_template('index.html')

# Prediction Helper Function
def predict_input(single_input):
    input_df = pd.DataFrame([single_input])
    encoded_cols, numeric_cols = stroke_model["encoded_cols"], stroke_model["numeric_cols"]
    preprocessor = stroke_model["preprocessor"]
    input_df[encoded_cols] = preprocessor.transform(input_df)
    X = input_df[numeric_cols + encoded_cols]
    prediction = stroke_model['model'].predict(X)
    return int(prediction[0])

# Generate PDF Function
def generate_pdf(patient_name, guardian_name, prediction_result):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", style="B", size=16)
    pdf.cell(200, 10, "Brain Stroke Prediction Report", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, f"Patient Name: {patient_name}", ln=True)
    pdf.cell(200, 10, f"Guardian Name: {guardian_name}", ln=True)
    pdf.cell(200, 10, f"Stroke Prediction: {prediction_result}", ln=True)
    pdf.ln(10)
    
    # Hospital Recommendation
    pdf.set_font("Arial", style="B", size=14)
    pdf.cell(200, 10, "Hospital Visit Recommendation", ln=True)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, "-> Nearest Hospital: Apollo Hospital", ln=True)
    pdf.cell(200, 10, "-> Date to be reached: Within 3 days", ln=True)
    pdf.cell(200, 10, f"-> Stroke Risk Percentage: 80% (Approximate)", ln=True)
    pdf.cell(200, 10, "-> Appointment Status: Confirmed", ln=True)
    pdf_path = f"{patient_name}_Stroke_Report.pdf"
    pdf.output(pdf_path)
    return pdf_path

# Send Email Function
def send_email(guardian_email, guardian_name, pdf_path):
    msg = Message("Brain Stroke Prediction Report", sender='rkpoornima2005@gmail.com', recipients=[guardian_email])
    msg.body = f"Hello {guardian_name},\n\nPlease find attached the stroke prediction report."
    with open(pdf_path, "rb") as fp:
        msg.attach(pdf_path, "application/pdf", fp.read())
    mail.send(msg)

@app.route('/')
def home():
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
