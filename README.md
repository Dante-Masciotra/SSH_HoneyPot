# SSH Honeypot

## Overview

This SSH Honeypot project is designed to protect Linux servers by detecting and logging unauthorized SSH access attempts. Implemented in Python, this honeypot provides a simple yet effective way to monitor and analyze potential security threats.

Developed as a course project by students, this project aims to enhance understanding of network security and Python programming.

## Features

- **Real-time monitoring**: Logs and monitors unauthorized SSH access attempts.
- **Detailed logging**: Captures detailed information about each access attempt.
- **Alert system**: Sends email notifications to administrators of potential security threats.

## Usage

1. **Generate an SSH key for the honeypot:**

   ```bash
    ssh-keygen -t rsa -b 2048 -f server.key
   ```

2. Run the honeypot:

   ```bash
     python honeypot.py
   ```

3. Monitor the logs:
   
     The honeypot creates logs in the ssh_honeypot.log file. Monitor these logs to analyze unauthorized access attempts.

## Authors

This project was created by:  

Dante Masciotra - [Website](https://dante-masciotra.github.io/)  
Zach Wasylyk - [GitHub](https://github.com/WasyMotto)  
