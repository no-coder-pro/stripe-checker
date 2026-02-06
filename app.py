from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from api import wulibike
import os

app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET'])
def home():
    """Serve the index page from root"""
    return send_from_directory('.', 'index.html')

@app.route('/api/stripe2', methods=['GET'])
def wulibike_payment():
    """Wulibike Payment Method API"""
    auth = request.args.get('auth', '')
    proxy = request.args.get('proxy', '')
    
    result, status_code = wulibike.handle_endpoint(auth, proxy)
    return jsonify(result), status_code

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
