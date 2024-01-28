<h1 align="center">Vuln-REST</h1>


![Docker Pulls](https://img.shields.io/docker/pulls/mrsecurecode/vuln-rest1)

Vuln-REST is a vulnerable REST API designed for educational purposes. This application exposes common security flaws found in APIs.



## This vulnerable application contains the following API vulnerabilities:
- Broken Object Level Authorization
- Broken Authentication
- Broken Object Property Level Authorization (mass assignment + Excessive Data Exposure)
- Broken Function Level Authorization
- Lack of Resources & Rate Limiting
- Server Side Request Forgery
- Local File Inclusion (LFI)
- Improper Inventory Management
- SQL Injection (SQLi)
- OS-Command Injection
- JWT Attacks


## Manual Installation

### Requirements
- Python3
- pip3
- MySQL

```
git clone https://github.com/Mr-Secure-Code/Vuln-REST.git
```
```
cd Vuln-REST
```
```
pip3 install -r requirements.txt
```
### Setting up the Database
-   Import **db.sql** into MySQL Database
- Configure the DB Credentials in the **app.py**

### Run 
```
python3 app.py
```

## Installation with Docker
**To quickly set up the vulnerable REST API using Docker, follow these steps:**

```
docker pull mrsecurecode/vuln-rest1
```
```
docker run -d -p 3306:3306 -p 80:80 --name my-vul-api mrsecurecode/vuln-rest1 /bin/bash -c "service mariadb restart && python3 app.py"
```
