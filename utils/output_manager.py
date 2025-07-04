class OutputManager:
    """Handles output formatting and report generation for FuzzMaster results."""
    def generate_html_report(self, results_data):
        # Simple HTML report
        html = ["<html><head><title>FuzzMaster Report</title></head><body>"]
        html.append("<h1>FuzzMaster Scan Report</h1>")
        scan_info = results_data.get('scan_info', {})
        html.append(f"<h2>Target: {scan_info.get('target_url', '')}</h2>")
        html.append(f"<p>Scan Level: {scan_info.get('scan_level', '')}</p>")
        html.append(f"<p>Duration: {scan_info.get('duration', '')}</p>")
        html.append(f"<p>Total Requests: {scan_info.get('total_requests', '')}</p>")
        html.append(f"<p>Completed: {scan_info.get('completed_requests', '')}</p>")
        html.append(f"<p>Found Results: {scan_info.get('found_results', '')}</p>")
        html.append("<h2>Results</h2><table border='1'><tr><th>Status</th><th>URL</th><th>Length</th><th>Time</th></tr>")
        for result in results_data.get('results', []):
            html.append(f"<tr><td>{result.get('status_code')}</td><td>{result.get('url')}</td><td>{result.get('content_length')}</td><td>{result.get('response_time')}</td></tr>")
        html.append("</table>")
        if 'analysis' in results_data:
            html.append("<h2>Analysis</h2>")
            html.append(f"<p>Clusters: {results_data['analysis'].get('clusters', 0)}</p>")
            html.append(f"<pre>{results_data['analysis'].get('patterns', '')}</pre>")
        html.append("</body></html>")
        return '\n'.join(html)

    def generate_text_report(self, results_data):
        # Simple text report
        lines = ["FuzzMaster Scan Report"]
        scan_info = results_data.get('scan_info', {})
        lines.append(f"Target: {scan_info.get('target_url', '')}")
        lines.append(f"Scan Level: {scan_info.get('scan_level', '')}")
        lines.append(f"Duration: {scan_info.get('duration', '')}")
        lines.append(f"Total Requests: {scan_info.get('total_requests', '')}")
        lines.append(f"Completed: {scan_info.get('completed_requests', '')}")
        lines.append(f"Found Results: {scan_info.get('found_results', '')}")
        lines.append("\nResults:")
        for result in results_data.get('results', []):
            lines.append(f"[{result.get('status_code')}] {result.get('url')} ({result.get('content_length')} bytes, {result.get('response_time')}s)")
        if 'analysis' in results_data:
            lines.append("\nAnalysis:")
            lines.append(f"Clusters: {results_data['analysis'].get('clusters', 0)}")
            lines.append(str(results_data['analysis'].get('patterns', '')))
        return '\n'.join(lines) 