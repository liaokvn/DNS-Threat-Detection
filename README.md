# DNS Threat Detection

# Overview

This project simulates a common task performed by a SOC Analyst: analyzing DNS traffic to identify potential threats. Using Splunk SIEM, I ingested and normalized DNS log data to monitor for signs of malicious domain activity — a common vector used in Command-and-Control (C2), phishing, and domain-based malware campaigns.

I configured a custom source type to properly classify the logs, built search queries to extract indicators of compromise (IOCs), and injected a simulated malicious domain to test detection workflows. This mirrors the proactive threat-hunting and alert validation responsibilities typical in a Tier 1 or Tier 2 SOC role.

Through this hands-on approach, I demonstrated core SOC analyst skills such as log ingestion, detection engineering, IOC investigation, and DNS threat analysis.

# Data Ingestion

<img width="904" height="552" alt="Image" src="https://github.com/user-attachments/assets/1eeef30e-58ba-4ee5-ae65-64abfb3e9eea" />
In this step, I ingested raw DNS logs into Splunk to prepare for full-spectrum secruity analysis. Loading the dns.log.gz file allowed me to simulate real-world enterprise
ingestion pipelines. This phase mirrros the daily responsibilities of a SOC Analyst, where establishing data visibility is critical to uncovering threats. Without 
visibility into DNS telemetry, defenders are effectively blind to the most common forms of malicious communication. 

# Initial Event Validation

<img width="3431" height="1271" alt="Image" src="https://github.com/user-attachments/assets/f8f857b3-e96e-4b8b-a5ad-85810cba522a" />
Once the data was ingested, I validated that 844,000+ events were being indexed and parsed in real-time. I confirmed key fields like `host`, `source`, and `sourcetype` were properly extracted.
This wasn't just about checking box, it was about proving that the system was correctly interpreting raw log data and giving me control over every packet and query coming through the network. 
Effective threat detection starts with clean, structured data. 

# DNS Traffic Visbility

<img width="3429" height="1349" alt="Image" src="https://github.com/user-attachments/assets/16967c62-9183-48c4-9870-8b8e74b555fe" />
This is the intelligence phase. Using `stats count by src_ip, domain`, I was able to reveal which internal hosts were generating the most DNS queries and which domains they were contacting.
This gives immediate insight into potential beaconing behavior, misconfigurations, or lateral movement. It's like having night vision in the dark, suddenly, obscure traffic becomes patterns of interest. 

# Anomaly Detection 

<img width="3430" height="1350" alt="Image" src="https://github.com/user-attachments/assets/e7096867-77b9-401b-98db-205e78132c02" />
This shows, I pivoted to detected suspicious behavior by calculating how many unique domains each source IP queried. This approach surface outlines those hosts reaching out to a suspiciously high number of domains. 
This technique is often used to detect malware callbacks, C2 channels, or compromised endpoints. It's where raw data turns into actionable insight.

# Threat Hunting

<img width="3427" height="1356" alt="Image" src="https://github.com/user-attachments/assets/2e9bcc4c-9ae6-4485-9401-9bdf16bdb3a8" />
In this step, I moved beyond just parsing log data by hunting for real threats. By crafting regex-driven Splunk query, I filtered for DNS lookups that resolved to raw IP addreses instad of domains.
This is important because malware often bypasses traditional domain reputation checks by calling out to hardcoded IPs. 

What I found is one source IP, `192.168.202.110`, made repeated requests to a wide range of IP-based domains. This anomaly signals either misconfiguration or a possible compormise.

This step underscores my ability to operationalize Splunk as a hunting tool, not just a dashboard. 
I transformed a mountain of DNS logs into actionable intelligence, demonstrating both security and data analysis skills. 

# MITRE ATT&CK Integration 

<img width="565" height="262" alt="Image" src="https://github.com/user-attachments/assets/88777ac3-3688-4a68-87e3-4c4cae2dddce" />
<img width="292" height="433" alt="Image" src="https://github.com/user-attachments/assets/82f65d7a-6f22-49f0-8560-826cec32b5e1" />
<img width="3427" height="1351" alt="Image" src="https://github.com/user-attachments/assets/af3fa08e-bdab-4d91-ba73-ce3d8b3c8a60" />
<img width="3428" height="1355" alt="Image" src="https://github.com/user-attachments/assets/4c5c526d-c126-4b91-b624-b290f25d32c0" />

This step, I installed and configured MITRE ATT&CK Tactics and Technique Navigator app within the Splunk environment. This tool is designed to help cybersecurity analyst visually map and correlate security 
telemetry with the standardized tactics and technique outlined by MITRE's ATT&CK framework.

After launching the app, I accessed the Enterprised Attack Navigator, which displayed:
- 34 totla tactics (Defense Evasion, Credential Access, Lateral Movement)
- 211 total techniques, providing deep visbility into potential adversary behaviors 

In parallel, I rand a DNS log query to extract domain level statistics using:

`index=* sourcetype=dnslogs
| rex field=query "(?<domain>[a-zA-Z0-9\-\.]+)\.(?:[a-z]{2,})"
| stats count by domain
| sort -count`

This allowed me to identify the most frequently queried domains, which could later be cross-reference with MITRE technique catergories such as Command and Control (via DNS tunneling),
Exfiltration, or Initial Access from suspicious domains. 


# Summary 

This project showcased my ability operationalized threat detection through DNS log analysis using Splunk, combining data anlytics, regex parsing, and threat intelligence framwork to simulate a real-world security operations workflow.
Starting with raw DNS logs, I built custom search queries to extract key fields, identify suspicious domains, and visualize traffic patterns. I performed statistical analysis to uncover anomalies in query volume 
and souce IPs critical behaviors that may indicate beaconing, data exfiltration, or malware command and control acitivty.

To bring additional intelligence to my findings, I integrated the MITRE ATT&CK Navigator, correlating observed DNS activity with known attacker tactics and techniques. This provided a structured and threat informed 
approach to log analysis, aliging my investigation with industry standard threat models.

In doing so, I demonstrated core skills in:
- Log parsing and regex extraction
- Splunk’s SPL search language and visualizations
- Threat hunting and statistical analysis
- Applying frameworks like MITRE ATT&CK for deeper insight
