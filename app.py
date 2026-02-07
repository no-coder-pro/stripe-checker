from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from api import wulibike, cloudveil, eptes, anyelasvineyards, atriresearchresources, dashboardpack, grovebooks, jumilondon, nopong, shoprootscience
import os

app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET'])
def home():
    """Serve the index page from root"""
    return send_from_directory('.', 'index.html')

@app.route('/api/stripe1', methods=['GET'])
def cloudveil_payment():
    """Cloudveil Payment Method API"""
    auth = request.args.get('auth', '')
    proxy = request.args.get('proxy', '')
    
    result, status_code = cloudveil.handle_endpoint(auth, proxy)
    return jsonify(result), status_code

@app.route('/api/stripe2', methods=['GET'])
def wulibike_payment():
    """Wulibike Payment Method API"""
    auth = request.args.get('auth', '')
    proxy = request.args.get('proxy', '')
    
    result, status_code = wulibike.handle_endpoint(auth, proxy)
    return jsonify(result), status_code

@app.route('/api/stripe3', methods=['GET'])
def eptes_payment():
    """Eptes Payment Method API"""
    auth = request.args.get('auth', '')
    proxy = request.args.get('proxy', '')
    
    result, status_code = eptes.handle_endpoint(auth, proxy)
    return jsonify(result), status_code

@app.route('/api/stripe4', methods=['GET'])
def anyelasvineyards_payment():
    """Anyelas Vineyards Payment Method API"""
    auth = request.args.get('auth', '')
    proxy = request.args.get('proxy', '')
    
    result, status_code = anyelasvineyards.handle_endpoint(auth, proxy)
    return jsonify(result), status_code

@app.route('/api/stripe5', methods=['GET'])
def atriresearchresources_payment():
    """Atri Research Resources Payment Method API"""
    auth = request.args.get('auth', '')
    proxy = request.args.get('proxy', '')
    
    result, status_code = atriresearchresources.handle_endpoint(auth, proxy)
    return jsonify(result), status_code

@app.route('/api/stripe6', methods=['GET'])
def dashboardpack_payment():
    """DashboardPack Payment Method API"""
    auth = request.args.get('auth', '')
    proxy = request.args.get('proxy', '')
    
    result, status_code = dashboardpack.handle_endpoint(auth, proxy)
    return jsonify(result), status_code

@app.route('/api/stripe7', methods=['GET'])
def grovebooks_payment():
    """GroveBooks Registration Payment Method API"""
    auth = request.args.get('auth', '')
    proxy = request.args.get('proxy', '')
    
    result, status_code = grovebooks.handle_endpoint(auth, proxy)
    return jsonify(result), status_code

@app.route('/api/stripe8', methods=['GET'])
def jumilondon_payment():
    """Jumi London Registration Payment Method API"""
    auth = request.args.get('auth', '')
    proxy = request.args.get('proxy', '')
    
    result, status_code = jumilondon.handle_endpoint(auth, proxy)
    return jsonify(result), status_code

@app.route('/api/stripe9', methods=['GET'])
def nopong_payment():
    """No Pong Registration Payment Method API"""
    auth = request.args.get('auth', '')
    proxy = request.args.get('proxy', '')
    
    result, status_code = nopong.handle_endpoint(auth, proxy)
    return jsonify(result), status_code

@app.route('/api/stripe10', methods=['GET'])
def shoprootscience_payment():
    """Shop Root Science Registration Payment Method API"""
    auth = request.args.get('auth', '')
    proxy = request.args.get('proxy', '')
    
    result, status_code = shoprootscience.handle_endpoint(auth, proxy)
    return jsonify(result), status_code

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
