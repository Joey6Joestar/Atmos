from flask import Flask, render_template, request, redirect, url_for
import os

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = 'static/uploads'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def splash():
    return render_template('splash.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/upload', methods=['GET','POST'])
def upload():
    if request.method == 'POST':
        file = request.files.get('photo')

        if file:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)
            return f"Uploaded successfully: {file.filename}"
        
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)