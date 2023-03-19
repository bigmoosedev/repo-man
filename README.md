<h1>Repo-Man: Web App Security Toolkit</h1>

<p>
    SneakyPeeky is a collection of lightweight Python scripts for discovering potentially sensitive files and directories, subdomain enumeration, and basic web vulnerability scanning on web applications. The toolkit checks a list of known file paths, looks for common configuration files, log files, and other sensitive files that may have been accidentally exposed. Additionally, it provides subdomain enumeration and basic vulnerability scanning functionalities.
</p>

<h2>Features</h2>

<ul>
    <li>Quickly scans a list of known sensitive file paths on a target web application</li>
    <li>Simple and easy-to-use CLI interface</li>
    <li>Customizable list of file paths to check</li>
    <li>Subdomain enumeration using a wordlist</li>
    <li>Basic web vulnerability scanning</li>
</ul>

<h2>Installation</h2>

<ol>
    <li>Clone the repository or download the <code>sneaky_peeky.py</code>, <code>subdomain_enum.py</code>, and <code>web_vuln_scanner.py</code> scripts.</li>
    <li>Make sure you have Python 3.x installed on your system.</li>
    <li>Install the required Python packages using the following command:</li>
</ol>

<pre><code>pip install -r requirements.txt</code></pre>

<h2>Usage</h2>

<h3>Sensitive Files Scanner</h3>

<p>
    Run the SneakyPeeky script with the target web application URL as the argument:
</p>

<pre><code>python sneaky_peeky.py http://example.com</code></pre>

<p>
    SneakyPeeky will iterate through the list of known sensitive file paths and report any potentially exposed files or directories found on the target web application.
</p>

<h3>Subdomain Enumeration</h3>

<p>
    Run the <code>subdomain_enum.py</code> script with the domain and wordlist as arguments:
</p>

<pre><code>python subdomain_enum.py example.com wordlist.txt</code></pre>

<p>
    The script will enumerate subdomains based on the provided wordlist and output any discovered subdomains.
</p>

<h3>Web Vulnerability Scanner</h3>

<p>
    Run the <code>web_vuln_scanner.py</code> script with the target web application URL as the argument:
</p>

<pre><code>python web_vuln_scanner.py http://example.com
</code></pre>

<p>
    The script will perform basic web vulnerability scanning, including checking for common misconfigurations and vulnerabilities.
</p>

<h2>Customization</h2>

<p>
    You can customize the list of file paths to check by modifying the <code>sensitive_paths</code> variable in the <code>sneaky_peeky.py</code> script. Add or remove any paths as needed to fit your specific use case.
</p>

<h2>Disclaimer</h2>

<p>
    SneakyPeeky is for educational purposes and legal use only. Always obtain proper authorization before scanning any web applications. Unauthorized scanning may be illegal and unethical. For a more comprehensive vulnerability assessment, consider using established tools like OWASP ZAP or Burp Suite.
</p>
