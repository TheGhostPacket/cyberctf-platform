# 🚩 CyberCTF Platform

<div align="center">

![CyberCTF Platform](https://img.shields.io/badge/CyberCTF-Platform-brightgreen?style=for-the-badge)
![Flask](https://img.shields.io/badge/Flask-2.3.3-blue?style=for-the-badge&logo=flask)
![Python](https://img.shields.io/badge/Python-3.8+-yellow?style=for-the-badge&logo=python)
![SQLite](https://img.shields.io/badge/SQLite-Database-lightgrey?style=for-the-badge&logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A comprehensive Capture The Flag (CTF) platform for cybersecurity education and training**

[🚀 Live Demo](https://cyberctf-platform.onrender.com) • [🐛 Report Bug](https://github.com/TheGhostPacket/cyberctf-platform/issues) • [💡 Request Feature](https://github.com/TheGhostPacket/cyberctf-platform/issues)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Demo](#-demo)
- [Technology Stack](#-technology-stack)
- [Installation](#-installation)
- [Usage](#-usage)
- [Challenge Categories](#-challenge-categories)
- [API Documentation](#-api-documentation)
- [Deployment](#-deployment)
- [Contributing](#-contributing)
- [Security](#-security)
- [License](#-license)
- [Contact](#-contact)

---

## 🎯 Overview

CyberCTF Platform is a professional-grade Capture The Flag (CTF) platform designed for cybersecurity education and training. Built with Flask and featuring real-time challenges across multiple security domains, it provides an engaging way to learn cybersecurity concepts through hands-on practice.

**Perfect for:**
- 🎓 **Educational institutions** teaching cybersecurity
- 🏢 **Corporate training** programs  
- 👨‍💻 **Individual learners** wanting to practice security skills
- 🏆 **CTF competitions** and events

---

## ✨ Features

### 🏆 **Competition Features**
- **Multi-Category Challenges** - Web Security, Cryptography, Network Security, Password Cracking, Reverse Engineering
- **Real-Time Scoring System** - Live point tracking and leaderboard updates
- **Progressive Difficulty** - Challenges ranging from beginner to advanced
- **Hint System** - Guided learning with helpful hints

### 👥 **User Management**
- **Secure Authentication** - Password hashing with Werkzeug
- **User Profiles** - Track progress and achievements
- **Session Management** - Secure user sessions
- **Registration System** - Easy account creation

### 📊 **Analytics & Tracking**
- **Live Leaderboard** - Real-time competition rankings
- **Progress Tracking** - Monitor solved challenges and scores
- **Submission History** - Track all flag submission attempts
- **Performance Statistics** - Detailed user analytics

### 🎨 **User Experience**
- **Modern Hacker-Themed UI** - Immersive cybersecurity aesthetic
- **Mobile Responsive** - Works on all devices
- **Real-Time Feedback** - Instant success/error notifications
- **Intuitive Navigation** - Easy-to-use interface

---

## 🎮 Demo

### 🌐 **Live Demo**
Try the platform: **[https://cyberctf-platform.onrender.com](https://cyberctf-platform.onrender.com)**

### 🧪 **Test Credentials**
```
Registration: Create your own account
Sample Challenges Available: 7 challenges across 5 categories
```

### 📸 **Screenshots**

<div align="center">

| Home Page | Dashboard | Challenges |
|-----------|-----------|------------|
| ![Home](https://via.placeholder.com/300x200?text=Home+Page) | ![Dashboard](https://via.placeholder.com/300x200?text=Dashboard) | ![Challenges](https://via.placeholder.com/300x200?text=Challenges) |

</div>

---

## 🛠️ Technology Stack

### **Backend**
- **Flask 2.3.3** - Python web framework
- **SQLite** - Lightweight database
- **Werkzeug** - Password hashing and security
- **Python 3.8+** - Programming language

### **Frontend**
- **HTML5 & CSS3** - Modern web standards
- **JavaScript (Vanilla)** - Interactive functionality
- **Font Awesome** - Icon library
- **Responsive Design** - Mobile-friendly layout

### **Deployment**
- **Render.com** - Cloud hosting platform
- **Gunicorn** - Python WSGI HTTP Server
- **Git** - Version control

---

## 🚀 Installation

### **Prerequisites**
- Python 3.8 or higher
- Git
- Web browser

### **Local Development Setup**

1. **Clone the repository**
```bash
git clone https://github.com/TheGhostPacket/cyberctf-platform.git
cd cyberctf-platform
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Run the application**
```bash
python app.py
```

5. **Open in browser**
```
http://localhost:5000
```

### **Docker Setup** (Optional)
```bash
# Build image
docker build -t cyberctf-platform .

# Run container
docker run -p 5000:5000 cyberctf-platform
```

---

## 📖 Usage

### **Getting Started**

1. **Register an Account**
   - Visit the registration page
   - Create username, email, and password
   - Login to access challenges

2. **Choose Challenge Category**
   - Navigate to Dashboard
   - Select from available categories
   - View difficulty and point values

3. **Solve Challenges**
   - Read challenge descriptions
   - Find hidden flags
   - Submit in format: `FLAG{solution}`
   - Use hints if needed

4. **Track Progress**
   - View your score on dashboard
   - Check leaderboard rankings
   - Monitor solved challenges

### **Challenge Format**
All flags follow the format: `FLAG{content}`

Example: `FLAG{welcome_to_ctf}`

---

## 🎯 Challenge Categories

### 🔓 **Web Security** (2 challenges)
- **Basic Flag Hunt** (100 pts) - HTML source code analysis
- **SQL Injection** (250 pts) - Database bypass techniques

**Sample Solutions:**
```
Basic Flag Hunt: FLAG{welcome_to_ctf}
SQL Injection: FLAG{sql_injection_master}
```

### 🔐 **Cryptography** (2 challenges)
- **Caesar Cipher** (150 pts) - ROT13 decoding
- **Base64 Decoder** (120 pts) - Base64 decryption

**Sample Solutions:**
```
Caesar Cipher: FLAG{CRYPTO_IS_FUN}
Base64 Decoder: FLAG{base64_decoding}
```

### 🔑 **Password Cracking** (1 challenge)
- **Weak Password** (200 pts) - MD5 hash cracking

**Sample Solution:**
```
Weak Password: FLAG{hello}
```

### 🌐 **Network Security** (1 challenge)
- **Network Analysis** (100 pts) - Protocol identification

**Sample Solution:**
```
Network Analysis: FLAG{HTTPS}
```

### 🔍 **Reverse Engineering** (1 challenge)
- **Binary Analysis** (180 pts) - Binary to ASCII conversion

**Sample Solution:**
```
Binary Analysis: FLAG{binary}
```

---

## 🔌 API Documentation

### **Authentication Endpoints**
```
POST /register    - Create new user account
POST /login       - User authentication
GET  /logout      - End user session
```

### **Challenge Endpoints**
```
GET  /dashboard           - User dashboard
GET  /challenges/<category> - Category challenges
POST /submit_flag         - Submit challenge solution
GET  /leaderboard        - Competition rankings
```

### **Response Format**
```json
{
  "success": "Operation successful message",
  "error": "Error description if failed"
}
```

---

## 🌐 Deployment

### **Deploy to Render**

1. **Fork this repository**
2. **Connect to Render:**
   - Visit [render.com](https://render.com)
   - Create new Web Service
   - Connect GitHub repository

3. **Configure deployment:**
   ```
   Build Command: pip install -r requirements.txt
   Start Command: python app.py
   Environment: Python 3
   ```

4. **Environment Variables** (Optional):
   ```
   FLASK_ENV=production
   SECRET_KEY=your-secret-key-here
   ```

### **Deploy to Heroku**
```bash
# Install Heroku CLI and login
heroku create your-app-name
git push heroku main
```

### **Deploy to AWS/DigitalOcean**
Detailed deployment guides available in the `docs/` folder.

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### **Ways to Contribute**
- 🐛 **Bug Reports** - Report issues you find
- 💡 **Feature Requests** - Suggest new features
- 🔧 **Code Contributions** - Submit pull requests
- 📚 **Documentation** - Improve docs and tutorials
- 🎯 **New Challenges** - Add more CTF challenges

### **Development Process**

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Test thoroughly**
5. **Submit a pull request**

### **Adding New Challenges**
```python
# Add to challenges list in app.py
{
    'title': 'Your Challenge Name',
    'description': 'Challenge description with instructions',
    'category': 'Web Security',  # or other category
    'points': 300,
    'flag': 'FLAG{your_solution_here}',
    'hint': 'Helpful hint for users',
    'challenge_data': 'Additional challenge data if needed'
}
```

### **Code Style**
- Follow PEP 8 for Python code
- Use meaningful variable names
- Add comments for complex logic
- Test all new features

---

## 🔒 Security

### **Security Features**
- ✅ **Password Hashing** - Werkzeug secure hashing
- ✅ **Session Management** - Secure user sessions
- ✅ **Input Validation** - Prevent injection attacks
- ✅ **SQL Injection Protection** - Parameterized queries
- ✅ **XSS Prevention** - Template escaping

### **Reporting Security Issues**
If you discover a security vulnerability, please send an e-mail to:
📧 **contact@theghostpacket.com**

**Please do not open public issues for security vulnerabilities.**

---

## 📊 Project Statistics

- **7** Total Challenges
- **5** Challenge Categories  
- **100+** Lines of Python Code
- **500+** Lines of HTML/CSS/JS
- **Mobile Responsive** Design
- **Real-Time** Features

---

## 🗺️ Roadmap

### **Version 2.0** (Planned)
- [ ] **Team Competition Mode**
- [ ] **Real-Time Chat System**
- [ ] **Admin Panel** for challenge management
- [ ] **Email Verification** system
- [ ] **Social Login** (Google, GitHub)
- [ ] **Achievement System** with badges
- [ ] **API for External Tools**
- [ ] **Docker Containerization**

### **Version 2.1** (Future)
- [ ] **Advanced Analytics Dashboard**
- [ ] **Custom Challenge Builder**
- [ ] **Tournament Mode**
- [ ] **Mobile App** (React Native)
- [ ] **Integration with Security Tools**

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 TheGhostPacket

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 📞 Contact & Support

<div align="center">

### **Created by TheGhostPacket**

[![Portfolio](https://img.shields.io/badge/Portfolio-theghostpacket.com-blue?style=for-the-badge&logo=firefox)](https://theghostpacket.com)
[![GitHub](https://img.shields.io/badge/GitHub-TheGhostPacket-black?style=for-the-badge&logo=github)](https://github.com/TheGhostPacket)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-nhyira--yanney-blue?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/nhyira-yanney-b19898178)
[![Email](https://img.shields.io/badge/Email-contact@theghostpacket.com-red?style=for-the-badge&logo=gmail)](mailto:contact@theghostpacket.com)

</div>

### **Support**
- 📧 **Email**: contact@theghostpacket.com
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/TheGhostPacket/cyberctf-platform/issues)
- 💬 **Feature Requests**: [GitHub Discussions](https://github.com/TheGhostPacket/cyberctf-platform/discussions)

### **Acknowledgments**
- **Flask Community** for the excellent web framework
- **Cybersecurity Community** for inspiration and best practices
- **Open Source Contributors** who make projects like this possible

---

<div align="center">

### **⭐ Star this project if you found it helpful!**

**Built with ❤️ for the cybersecurity community**

![Visitor Count](https://visitor-badge.glitch.me/badge?page_id=TheGhostPacket.cyberctf-platform)

</div>

---

## 📈 GitHub Stats

![GitHub stars](https://img.shields.io/github/stars/TheGhostPacket/cyberctf-platform?style=social)
![GitHub forks](https://img.shields.io/github/forks/TheGhostPacket/cyberctf-platform?style=social)
![GitHub issues](https://img.shields.io/github/issues/TheGhostPacket/cyberctf-platform)
![GitHub pull requests](https://img.shields.io/github/issues-pr/TheGhostPacket/cyberctf-platform)

**Last Updated**: January 2025