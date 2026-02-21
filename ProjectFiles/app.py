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
        party_prompt = request.form.get('partyPrompt')

        if not file or file.filename == '':
            return render_template('upload.html', success=False, filename=None, party_prompt=None)
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        return render_template('upload.html', success=True, filename=file.filename, party_prompt=party_prompt)
    
    return render_template('upload.html', success=False, filename=None, party_prompt=None)

if __name__ == '__main__':
    app.run(debug=True)