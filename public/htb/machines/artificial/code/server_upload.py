from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.route('/', methods=['POST'])
def handle_post():
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            # Save the file (or process it)
            file.save(os.path.join('uploads', file.filename))
            return jsonify({"status": "success", "filename": file.filename, "size": len(file.read())})
    
    return jsonify({"status": "error", "message": "No file received"})

if __name__ == '__main__':
    # Create uploads directory if it doesn't exist
    os.makedirs('uploads', exist_ok=True)
    app.run(host='0.0.0.0', port=8000, debug=True)