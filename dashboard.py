from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO
import json
import os
import yaml
import time
import threading
import datetime

# Load config
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.yaml')
with open(CONFIG_PATH, 'r') as f:
    config = yaml.safe_load(f)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'proxy_analyzer_dashboard_secret'  # Change this in production
socketio = SocketIO(app)

# In-memory log storage (will be replaced by file-based in production)
logs = []
alerts = []
report_data = {}

# Authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if (request.form.get('username') == config['dashboard']['username'] and
                request.form.get('password') == config['dashboard']['password']):
            session['logged_in'] = True
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

# Dashboard routes
@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html', 
                          config=config,
                          logs=logs[-50:],  # Show last 50 logs
                          alerts=alerts[-20:])  # Show last 20 alerts

@app.route('/logs')
def view_logs():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('logs.html', logs=logs[-100:])  # Show last 100 logs

@app.route('/alerts')
def view_alerts():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('alerts.html', alerts=alerts)

@app.route('/report')
def view_report():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Load the latest report
    try:
        report_file = config['report']['report_file']
        if os.path.exists(report_file):
            with open(report_file, 'r') as f:
                report_data = json.load(f)
        else:
            report_data = {}
    except Exception as e:
        report_data = {'error': str(e)}
    
    return render_template('report.html', report=report_data)

# API endpoints for data
@app.route('/api/logs')
def api_logs():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify(logs[-50:])

@app.route('/api/alerts')
def api_alerts():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify(alerts[-20:])

@app.route('/api/report')
def api_report():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        report_file = config['report']['report_file']
        if os.path.exists(report_file):
            with open(report_file, 'r') as f:
                report_data = json.load(f)
        else:
            report_data = {}
    except Exception as e:
        report_data = {'error': str(e)}
    
    return jsonify(report_data)

# WebSocket for real-time updates
@socketio.on('connect')
def handle_connect():
    if not session.get('logged_in'):
        return False  # Reject connection if not logged in

# Function to add a log entry (called from other modules)
def add_log(level, message):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = {
        'timestamp': timestamp,
        'level': level,
        'message': message
    }
    logs.append(log_entry)
    socketio.emit('new_log', log_entry)
    
    # If it's a warning or error, also add to alerts
    if level in ['WARNING', 'ERROR']:
        alerts.append(log_entry)
        socketio.emit('new_alert', log_entry)

# Background thread to monitor report file for changes
def monitor_report_file():
    last_modified = 0
    while True:
        try:
            report_file = config['report']['report_file']
            if os.path.exists(report_file):
                current_modified = os.path.getmtime(report_file)
                if current_modified > last_modified:
                    last_modified = current_modified
                    with open(report_file, 'r') as f:
                        report_data = json.load(f)
                    socketio.emit('report_updated', report_data)
        except Exception as e:
            print(f"Error monitoring report file: {e}")
        time.sleep(config['dashboard']['refresh_interval'])

# Start the dashboard
def run_dashboard():
    if config['dashboard']['enabled']:
        # Start the report monitor thread
        monitor_thread = threading.Thread(target=monitor_report_file)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Start the Flask app
        host = config['dashboard']['host']
        port = config['dashboard']['port']
        socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
        
if __name__ == '__main__':
    run_dashboard()
