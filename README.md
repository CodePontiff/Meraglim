# Meraglim

**Meraglim** is a web reconnaissance framework designed to help map web attack surfaces and support **manual investigation and learning**, not automated exploitation or vulnerability scanning.

Meraglim focuses on **pattern recognition, signal-based analysis, and reasoning**, aiming to guide users—especially beginners—towards understanding *how to think during web reconnaissance*, rather than producing severity scores or vulnerability claims.

> Meraglim is a recon reasoning tool, not a scanner.

---

## ✨ Key Features

- **Endpoint & Subdomain Discovery**  
  Identify reachable endpoints and subdomains as part of attack surface mapping.

- **JavaScript Analysis**  
  Extract endpoints, references, and API paths from JavaScript files and source maps.

- **Signal-Based Endpoint Classification**  
  Categorize endpoints based on observable signals such as:
  - authentication-related paths
  - user-controlled parameters
  - upload or file-handling behavior
  - configuration or debug indicators

- **Response Behavior Verification**  
  Observe how endpoints respond to different HTTP methods and status codes (e.g., 200, 401, 403).

- **Endpoint Harvesting**  
  Store discovered endpoints as reusable wordlists for future reconnaissance sessions.

- **Investigation Guidance**  
  Provide contextual hints to help users decide what may be worth manual inspection—without claiming vulnerabilities.

---

## 🧠 Design Philosophy

- ❌ Not an automated vulnerability scanner  
- ❌ No exploit execution  
- ❌ No severity labels (Critical / High / Medium / Low)  

- ✅ Signal-based, not verdict-based  
- ✅ Educational and exploration-focused  
- ✅ Manual validation is always required  

Meraglim does **not** determine exploitability, impact, or risk.  
All findings are **pattern-based observations**, not security conclusions.

---

## 🌐 Architecture

Meraglim runs as a web-based application and can be hosted locally or within a shared network environment.

This allows:
- Access from multiple devices on the same network
- Centralized reconnaissance workflow
- Browser-based interaction without client-side installations

> ⚠️ Meraglim is currently intended for trusted environments (localhost or private networks only for safety).

---

## 🚧 Project Status

Meraglim is **actively still on development**.

Features, logic, and user experience are still evolving as the framework is refined and tested.  
Expect breaking changes and ongoing improvements.

---

## 🎯 Intended Audience

- Beginners learning web reconnaissance
- Security students and CTF players
- Junior pentesters exploring attack surface mapping
- Anyone interested in recon **reasoning**, not automated results

---

## ⚠️ Disclaimer

Meraglim is intended for **educational and authorized security testing only**.  
Always ensure you have explicit permission before scanning any target.

---

## 📌 Summary

Meraglim does not tell you *what is vulnerable*.  
It helps you understand *what might be worth looking at—and why*.

