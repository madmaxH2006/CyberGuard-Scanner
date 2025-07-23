import os
from flask import Flask, render_template, request, flash, redirect, url_for
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = 'a_very_secure_and_random_secret_key'

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VIRUSTOTAL_API_KEY:
    raise ValueError("API Key Error: VIRUSTOTAL_API_KEY environment variable not set!")

VT_API_URL_BASE = 'https://www.virustotal.com/api/v3/'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze-url', methods=['POST'])
def analyze_url():
    submitted_url = request.form.get('url_to_analyze')
    if not submitted_url:
        flash("Please enter a URL to analyze.")
        return redirect(url_for('index'))

    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    payload = {'url': submitted_url}
    
    try:
        response = requests.post(VT_API_URL_BASE + 'urls', headers=headers, data=payload)
        response.raise_for_status()
        
        analysis_id = response.json()['data']['id']
        report_url = VT_API_URL_BASE + 'analyses/' + analysis_id
        
        report_response = requests.get(report_url, headers=headers)
        report_response.raise_for_status()
        
        report_data = report_response.json()['data']['attributes']
        stats = report_data['stats']
        total_votes = stats['harmless'] + stats['malicious']

        return render_template('report_url.html', 
                               item=submitted_url, 
                               stats=stats,
                               total=total_votes,
                               malicious=stats.get('malicious', 0))

    except requests.exceptions.RequestException as e:
        flash(f"API Error: Could not communicate with VirusTotal. {e}")
    except (KeyError, TypeError) as e:
        flash(f"Parsing Error: Could not parse the API response. {e}")
        
    return redirect(url_for('index'))


@app.route('/analyze-file', methods=['POST'])
def analyze_file():
    if 'file_to_analyze' not in request.files:
        flash('No file part in the request.')
        return redirect(url_for('index'))
    
    file = request.files['file_to_analyze']

    if file.filename == '':
        flash('No file selected.')
        return redirect(url_for('index'))

    if file:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        files = {'file': (file.filename, file.stream, 'application/octet-stream')}
        
        try:
            response = requests.post(VT_API_URL_BASE + 'files', headers=headers, files=files)
            response.raise_for_status()

            analysis_id = response.json()['data']['id']
            report_url = VT_API_URL_BASE + 'analyses/' + analysis_id
            
            report_response = requests.get(report_url, headers=headers)
            report_response.raise_for_status()
            
            report_data = report_response.json()['data']['attributes']
            stats = report_data['stats']
            total_votes = stats['harmless'] + stats['malicious']
            
            return render_template('report_file.html', 
                                   item=file.filename,
                                   stats=stats,
                                   total=total_votes,
                                   malicious=stats.get('malicious', 0))

        except requests.exceptions.RequestException as e:
            flash(f"API Error: Could not communicate with VirusTotal. The file might be too large for the free API. Error: {e}")
        except (KeyError, TypeError) as e:
            flash(f"Parsing Error: Could not parse the API response. {e}")

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)