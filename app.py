from flask import Flask, render_template, request, jsonify
from scanner import scan_domain

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/result')
def result():
    return render_template('result.html')

@app.route('/api/scan', methods=['GET'])
def api_scan():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    
    scan_results = scan_domain(domain)
    return jsonify(scan_results)

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)

