from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner import VulnerabilityScanner
import threading

app = Flask(__name__)
CORS(app)

scan_results = {}
active_scans = {}

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({'status': 'active', 'message': 'Vulnerability scanner is running'})

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    url = data.get('url')
    crawl_depth = data.get('crawl_depth', 3)
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    scan_id = str(len(scan_results) + 1)
    
    active_scans[scan_id] = {'url': url, 'status': 'running', 'progress': 0}
    
    def run_scan():
        try:
            scanner = VulnerabilityScanner()
            results = scanner.scan(url, crawl_depth=crawl_depth)
            scan_results[scan_id] = results
            active_scans[scan_id]['status'] = 'completed'
            active_scans[scan_id]['progress'] = 100
        except Exception as e:
            scan_results[scan_id] = {'error': str(e), 'url': url, 'findings': [], 'stats': {}}
            active_scans[scan_id]['status'] = 'failed'
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id, 'status': 'started', 'message': f'Scan started for {url}'})

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    elif scan_id in active_scans:
        return jsonify({
            'status': active_scans[scan_id]['status'],
            'progress': active_scans[scan_id]['progress'],
            'message': 'Scan in progress'
        })
    else:
        return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/scans', methods=['GET'])
def get_all_scans():
    return jsonify({'active': active_scans, 'completed': scan_results})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001, use_reloader=False)