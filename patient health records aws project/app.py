import boto3
import uuid
from datetime import datetime
from flask import Flask, request, session,redirect,render_template
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = '1234567890'

# AWS Configuration
DYNAMO_TABLE = 'users'
HEALTH_RECORDS_TABLE = 'health_records'
S3_BUCKET = 'patient-records-c9'
# Initialize AWS DynamoDB
dynamodb = boto3.resource(
    'dynamodb',
    
)
table = dynamodb.Table(DYNAMO_TABLE)

health_records_table = dynamodb.Table(HEALTH_RECORDS_TABLE)


s3_client = boto3.client(
    's3',
    
)

@app.route('/')
def home():
    return render_template('landing.html')

@app.route('/registerpage')
def index():
    return render_template('register.html')

@app.route('/loginpage')
def loginpage():
    return render_template('login.html')

@app.route('/registerUser', methods=['POST'])
def register_user():
    email = request.form['email']
    username = request.form['username']
    password = request.form['password']

    table.put_item(
        Item={
            'email': email,
            'username': username,
            'password': password
        }
    )
    return render_template('login.html')

@app.route('/loginUser', methods=['POST'])
def login_user():
    email = request.form['email']
    password = request.form['password']

    try:
        response = table.get_item(
            Key={'email': email}
        )

        user = response.get('Item')
        print(user)
        if user and user['password'] == password:
            print("login")
            session['email'] = email
            return redirect('/dashboard')

        return render_template('login.html', error="Invalid credentials")

    except Exception as e:
        print(f"Error: {str(e)}")
        return render_template('login.html', error="Login failed")

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect('/')

    user = table.get_item(
        Key={'email': session['email']}
    ).get('Item', {})

    session['username']=user['username']
    return render_template('dashboard.html', username=session['username'])

def upload_health_record(file, category):
    if 'email' not in session:
        print("Error: User not logged in")
        return None

    try:
        # Generate a unique filename using UUID
        unique_filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
        
        # Generate a unique file_id (could also use a timestamp here)
        file_id = str(uuid.uuid4())

        # Upload file to S3
        s3_client.upload_fileobj(
            file, 
            S3_BUCKET, 
            unique_filename,
            ExtraArgs={'ContentType': file.content_type}
        )

        # S3 file URI
        file_uri = f"https://{S3_BUCKET}.s3.us-east-1.amazonaws.com/{unique_filename}"
        
        # Store record in DynamoDB with the new composite key (email + file_id)
        health_records_table.put_item(
            Item={
                'email': session['email'],  # Partition key
                'file_id': file_id,  # Sort key
                'file_uri': file_uri,
                'category': category,
                'uploaded_at': datetime.utcnow().isoformat(),
                'filename': unique_filename
            }
        )

        print(f"Upload successful: {file_uri}")
        
        return file_uri

    except Exception as e:
        print(f"Upload error: {str(e)}")  # Log the error
        return None


@app.route('/upload_health_record', methods=['POST'])
def handle_health_record_upload():
    if 'email' not in session:
        return "User not logged in", 403

    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    category = request.form.get('category')

    if file.filename == '':
        return "No selected file", 400

    result = upload_health_record(file, category)

    if result:
        return "File uploaded successfully", 200
    else:
        return "Upload failed", 500

@app.route('/myrecords')
def myrecords():
    return render_template("my-records.html")

from flask import jsonify

@app.route('/get_health_records', methods=['GET'])
def get_health_records():
    if 'email' not in session:
        return jsonify({"error": "User not logged in"}), 403  # Unauthorized access

    email = session['email']
    category = request.args.get('category', 'all')  # Default to 'all' if no category is provided

    try:
        # Set the base filter expression
        filter_expression = "email = :email"
        expression_values = {":email": email}

        # If a category is selected, filter by it
        if category != 'all':
            filter_expression += " AND category = :category"
            expression_values[":category"] = category

        # Query DynamoDB
        response = health_records_table.scan(
            FilterExpression=filter_expression,
            ExpressionAttributeValues=expression_values
        )

        records = response.get('Items', [])
        print(records)
        return jsonify({"records": records}), 200  # Success

    except Exception as e:
        print(f"Error fetching records: {str(e)}")
        return jsonify({"error": "Failed to fetch records"}), 500  # Internal Server Error

@app.route('/delete_health_record', methods=['POST'])
def delete_health_record():
    if 'email' not in session:
        return jsonify({"error": "User not logged in"}), 403  # Unauthorized access

    file_id = request.json.get('file_id')
    
    if not file_id:
        return jsonify({"error": "File ID is required"}), 400

    try:
        # Get the health record from DynamoDB
        response = health_records_table.get_item(
            Key={'email': session['email'], 'file_id': file_id}
        )

        record = response.get('Item')
        if not record:
            return jsonify({"error": "Record not found"}), 404

        # Delete the file from S3
        s3_client.delete_object(
            Bucket=S3_BUCKET,
            Key=record['filename']
        )

        # Delete the record from DynamoDB
        health_records_table.delete_item(
            Key={'email': session['email'], 'file_id': file_id}
        )

        return jsonify({"message": "Record deleted successfully"}), 200

    except Exception as e:
        print(f"Error deleting record: {str(e)}")
        return jsonify({"error": "Failed to delete record"}), 500



@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)