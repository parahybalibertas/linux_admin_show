document.addEventListener('DOMContentLoaded', function () {
    const modules = [
        {
            title: "Module 2: System Services",
            exercises: [
                {
                    title: "Exercise 2.1: Verify Installation of vsftpd and ftp",
                    why: "Ensuring that the necessary software is installed is crucial before trying to configure or use it.",
                    steps: [
                        "Steps for Ubuntu:",
                        "Open a terminal.",
                        "Check if vsftpd and ftp are installed with `dpkg -l | grep -E \"vsftpd|ftp\"`.",
                        "If they are not installed, install them using:",
                        "`sudo apt update && sudo apt install vsftpd ftp`",
                        "",
                        "Steps for CentOS:",
                        "Open a terminal.",
                        "Check installation with `rpm -q vsftpd ftp`.",
                        "If not installed, use:",
                        "`sudo yum install vsftpd ftp`",
                        "",
                        "Steps for OpenSUSE:",
                        "Open a terminal.",
                        "Check with `zypper se vsftpd ftp`.",
                        "Install with:",
                        "`sudo zypper install vsftpd ftp`"
                    ].join('<br>')
                },
                // Additional exercises can follow the same structure as above.
                {
                    title: "Exercise 2.2: Manually Start the vsftpd Service",
                    why: "Understanding how to manually control services is essential for system administration.",
                    steps: [
                        "Stop the service if it’s already running:",
                        "`sudo systemctl stop vsftpd`",
                        "",
                        "Start the service:",
                        "`sudo systemctl start vsftpd`",
                        "",
                        "Verify it is running:",
                        "`sudo systemctl status vsftpd`"
                    ].join('<br>')
                },
                {
                    title: "Exercise 2.3: Start vsftpd with SYSV Init Script (Optional)",
                    why: "Older systems or certain applications still use SYSV init scripts instead of systemd.",
                    steps: [
                        "Check if init scripts exist and start the service:",
                        "<code>sudo service vsftpd start</code>",
                        "",
                        "Confirm the service is running:",
                        "<code>sudo service vsftpd status</code>"
                    ].join('<br>')
                },
                {
                    title: "Exercise 2.4: Start vsftpd with systemd",
                    why: "Systemd is the modern system and service manager in Linux, replacing older init scripts.",
                    steps: [
                        "Start the service using systemd:",
                        "<code>sudo systemctl start vsftpd</code>",
                        "",
                        "Ensure it is active:",
                        "<code>sudo systemctl is-active vsftpd</code>"
                    ].join('<br>')
                },
                {
                    title: "Exercise 2.5: Enable vsftpd to Start on Boot",
                    why: "Services often need to be available immediately upon boot without manual intervention.",
                    steps: [
                        "Enable the service:",
                        "<code>sudo systemctl enable vsftpd</code>",
                        "",
                        "Verify that it's set to start on boot:",
                        "<code>sudo systemctl is-enabled vsftpd</code>"
                    ].join('<br>')
                },
                {
                    title: "Exercise 2.6: Customize a systemd Service",
                    why: "Customization can optimize the service for specific needs or environments.",
                    steps: [
                        "Copy the original service file to the `/etc/systemd/system` directory:",
                        "<code>sudo cp /lib/systemd/system/vsftpd.service /etc/systemd/system/vsftpd_custom.service</code>",
                        "",
                        "Edit the copied service file to make desired changes, for instance, changing the default FTP directory or adjusting the service's parameters.",
                        "Reload the systemd manager configuration:",
                        "<code>sudo systemctl daemon-reload</code>",
                        "",
                        "Start the custom service:",
                        "<code>sudo systemctl start vsftpd_custom.service</code>",
                        "",
                        "Verify it's running:",
                        "<code>sudo systemctl status vsftpd_custom.service</code>"
                    ].join('<br>')
                },
                {
                    title: "Exercise 2.7: Check Service Status for Common Daemons",
                    why: "Regular checks on critical services ensure they are functioning as expected.",
                    steps: [
                        "Check HTTPD (Apache):",
                        "<code>sudo systemctl status apache2</code>",
                        "",
                        "Check MySQL:",
                        "<code>sudo systemctl status mysql</code>",
                        "",
                        "Check Cron:",
                        "<code>sudo systemctl status cron</code>"
                    ].join('<br>')
                },
                {
                    title: "Exercise 2.8: Configure and Test Cron Jobs",
                    why: "Cron jobs automate routine tasks, reducing manual work and ensuring consistency.",
                    steps: [
                        "Edit the cron table for the current user:",
                        "<code>crontab -e</code>",
                        "",
                        "Add a cron job, e.g., to back up a directory every day at midnight:",
                        "<code>0 0 * * * tar -czf /backup/home_`date +\\%Y\\%m\\%d`.tgz /home/user</code>",
                        "",
                        "Save and exit. The cron service will automatically pick up this new job."
                    ].join('<br>')
                },
                {
                    title: "Exercise 2.9: Manage User and Group Services",
                    why: "User and group management is fundamental for maintaining security and organizational policies.",
                    steps: [
                        "Add a new user:",
                        "<code>sudo adduser newuser</code>",
                        "",
                        "Modify a user (e.g., change the login shell):",
                        "<code>sudo usermod -s /bin/zsh newuser</code>",
                        "",
                        "Delete a user:",
                        "<code>sudo deluser newuser</code>",
                        "",
                        "Add a new group:",
                        "<code>sudo addgroup newgroup</code>",
                        "",
                        "Add a user to a group:",
                        "<code>sudo adduser newuser newgroup</code>"
                    ].join('<br>')
                },
                {
                    title: "Exercise 2.10: Configure Logging Services",
                    why: "Effective logging is crucial for monitoring system and application health, as well as for security auditing.",
                    steps: [
                        "Install `rsyslog` if it's not already installed:",
                        "<code>sudo apt-get install rsyslog</code>",
                        "",
                        "Edit the `rsyslog` configuration file to define what logs to capture and where to store them:",
                        "<code>sudo nano /etc/rsyslog.conf</code>",
                        "",
                        "Restart the service to apply changes:",
                        "<code>sudo systemctl restart rsyslog</code>"
                    ].join('<br>')
                },
            ]
        
        },
    
        {
            title: "Module 3: Network Configuration",
            exercises: [
                {
                    title: "Exercise 3.1: Record Existing Network Configuration",
                    why: "Understanding the current network configuration is essential before making any changes to ensure you can revert to a functional state if needed.",
                    steps: [
                        "Open a terminal.",
                        "Use `ip addr show` to list all network interfaces and their current settings, including IP addresses.",
                        "Use `ip route show` to view the routing table.",
                        "Record or screenshot this information for reference."
                    ].join('<br>')
                },
                {
                    title: "Exercise 3.2: Create Boot-Time Network Configuration",
                    why: "Ensuring the network configuration is correct at boot time avoids the need for manual configuration after each restart.",
                    steps: [
                        "Edit the network configuration file. This varies by distribution:",
                        "",
                        "Ubuntu: Edit `/etc/network/interfaces` or use Netplan typically under `/etc/netplan/`.",
                        "CentOS/RHEL: Edit `/etc/sysconfig/network-scripts/ifcfg-<interface-name>`.",
                        "OpenSUSE: Use YaST or edit `/etc/sysconfig/network/ifcfg-<interface-name>`.",
                        "",
                        "Set static IP configuration based on the previous exercise's recorded settings.",
                        "",
                        "Restart the network service to apply changes:",
                        "`sudo systemctl restart networking  # Ubuntu`",
                        "`sudo systemctl restart network     # CentOS/RHEL`",
                        "`sudo systemctl restart wicked      # OpenSUSE`",
                        "",
                        "Verify connectivity with `ping google.com` or another reliable host."
                    ].join('<br>')
                },
                {
                    title: "Exercise 3.3: Modify Network Configuration and Add Aliases",
                    why: "Adding aliases (additional IP addresses) to a network interface allows a single physical network interface to act as multiple logical interfaces.",
                    steps: [
                        "Edit the network configuration file for your interface as done in the previous exercise.",
                        "Add an alias with an additional IP address. For example, in CentOS:",
                        "`DEVICE=eth0:1`",
                        "`BOOTPROTO=static`",
                        "`ONBOOT=yes`",
                        "`IPADDR=192.168.1.101`",
                        "`NETMASK=255.255.255.0`",
                        "",
                        "Restart the network service and test the new configuration with `ping` from another machine."
                    ].join('<br>')
                },
                {
                    title: "Exercise 3.4: Restore DHCP Configuration",
                    why: "DHCP allows automatic IP addressing from a network server, simplifying management.",
                    steps: [
                        "Modify the network configuration file to use DHCP instead of static IPs.",
                        "Restart the network service.",
                        "Confirm the new IP address with `ip addr show`."
                    ].join('<br>')
                },
                {
                    title: "Exercise 3.5: Implement IPTables Rules",
                    why: "IPTables rules help manage and restrict network traffic for security and operational efficiency.",
                    steps: [
                        "Flush existing rules to start fresh:",
                        "`sudo iptables -F`",
                        "",
                        "Set default chain policies (drop or accept):",
                        "`sudo iptables -P INPUT DROP`",
                        "`sudo iptables -P FORWARD DROP`",
                        "`sudo iptables -P OUTPUT ACCEPT`",
                        "",
                        "Allow incoming SSH connections:",
                        "`sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT`",
                        "",
                        "Save the rules:",
                        "`sudo iptables-save > /etc/iptables/rules.v4`"
                    ].join('<br>')
                },
                {
                    title: "Exercise 3.6: Configure and Test DNS Settings",
                    why: "Correct DNS settings are crucial for resolving domain names to IP addresses.",
                    steps: [
                        "Edit `/etc/resolv.conf` to add nameserver entries:",
                        "`nameserver 8.8.8.8`",
                        "`nameserver 8.8.4.4`",
                        "",
                        "Test DNS resolution with `nslookup google.com`."
                    ].join('<br>')
                },
                {
                    title: "Exercise 3.7: Implement Static Routing",
                    why: "Static routing controls the traffic flow between networks and can improve performance or enhance security.",
                    steps: [
                        "Add a static route:",
                        "`sudo ip route add 192.168.2.0/24 via 192.168.1.1`",
                        "",
                        "Verify with `ip route show`."
                    ].join('<br>')
                },
                {
                    title: "Exercise 3.8: Analyze Network Traffic with Tcpdump",
                    why: "Monitoring network traffic helps in diagnosing network issues and inspecting packet flows for security analysis.",
                    steps: [
                        "Install tcpdump if not already installed:",
                        "`sudo apt install tcpdump  # Ubuntu`",
                        "",
                        "Capture packets:",
                        "`sudo tcpdump -i eth0`",
                        "",
                        "Analyze output for unexpected traffic or issues."
                    ].join('<br>')
                },
                {
                    title: "Exercise 3.9: Configure Network Time Protocol (NTP)",
                    why: "Synchronizing time across network devices is essential for security protocols and log synchronization.",
                    steps: [
                        "Install NTP:",
                        "`sudo apt install ntp`",
                        "",
                        "Configure `/etc/ntp.conf` to use preferred time servers.",
                        "",
                        "Restart the NTP service and check status:",
                        "`sudo systemctl restart ntp`",
                        "`sudo systemctl status ntp`"
                    ].join('<br>')
                },
                {
                    title: "Exercise 3.10: Set Up a Firewall with Firewalld or UFW",
                    why: "A firewall is a security tool used to control incoming and outgoing network traffic based on predetermined security rules.",
                    steps: [
                        "Steps for UFW (Ubuntu):",
                        "Install UFW:",
                        "`sudo apt install ufw`",
                        "",
                        "Enable UFW and configure default policies:",
                        "`sudo ufw default deny incoming`",
                        "`sudo ufw default allow outgoing`",
                        "",
                        "Allow specific services, e.g., SSH:",
                        "`sudo ufw allow ssh`",
                        "",
                        "Enable UFW:",
                        "`sudo ufw enable`",
                        "",
                        "Steps for Firewalld (CentOS/RHEL):",
                        "Install firewalld:",
                        "`sudo yum install firewalld`",
                        "",
                        "Start and enable firewalld:",
                        "`sudo systemctl start firewalld`",
                        "`sudo systemctl enable firewalld`",
                        "",
                        "Configure rules:",
                        "`sudo firewall-cmd --permanent --add-service=ssh`",
                        "`sudo firewall-cmd --reload`"
                    ].join('<br>')
                }
            ]
        },
        {
            title: "Module 4: Advanced Networking and Services",
            exercises: [
                {
                    title: "Exercise 4.1: Create an Intermittent Network Issue",
                    why: "Simulating network issues helps in testing the robustness of network configurations and preparing for troubleshooting.",
                    steps: [
                        "Install Tools: Use `tc` (Traffic Control) utility for network traffic management. If not installed:",
                        "`sudo apt-get install iproute2  # On Ubuntu`",
                        "",
                        "Simulate Network Latency and Loss: Use `tc` to add delay and packet loss:",
                        "`sudo tc qdisc add dev eth0 root netem delay 100ms loss 10%`",
                        "",
                        "Validate Issue: Use `ping` or `tcpdump` to observe the added latency and packet loss.",
                        "",
                        "Remove Configuration: To revert:",
                        "`sudo tc qdisc del dev eth0 root netem`",
                    ].join('<br>')
                },
                {
                    title: "Exercise 4.2: Verify SMTP Service is Localhost-Only",
                    why: "Restricting SMTP to localhost prevents unauthorized external access to the mail server, enhancing security.",
                    steps: [
                        "Check Listening Ports: Use `ss` or `netstat`:",
                        "`sudo ss -tuln | grep :25  # or use netstat if ss is not available`",
                        "",
                        "Confirm Binding: Ensure it shows `127.0.0.1:25` for SMTP, indicating it’s bound to localhost.",
                        "",
                        "Test Connectivity: Use `telnet` to connect to port 25 from both localhost and a remote machine to verify it only accepts connections from localhost.",
                    ].join('<br>')
                },
                {
                    title: "Exercise 4.3: Configure and Test DHCP Server",
                    why: "A DHCP server automates the IP configuration process, reducing manual setup for devices on the network.",
                    steps: [
                        "Install DHCP Server:",
                        "`sudo apt-get install isc-dhcp-server  # On Ubuntu`",
                        "",
                        "Configure DHCP Server: Edit `/etc/dhcp/dhcpd.conf` to define IP ranges and other settings.",
                        "",
                        "Start the Service:",
                        "`sudo systemctl start isc-dhcp-server`",
                        "",
                        "Verify Operation: Connect a client device and ensure it receives an IP address as configured.",
                    ].join('<br>')
                },
                {
                    title: "Exercise 4.4: Implement Advanced Packet Filtering",
                    why: "Advanced packet filtering strengthens network security by meticulously managing the traffic according to complex rules.",
                    steps: [
                        "Define iptables Rules: Configure rules to filter, drop, or modify traffic based on specific conditions, such as IP ranges, ports, or protocols.",
                        "",
                        "Implement Rules:",
                        "`sudo iptables -A INPUT -p tcp --dport 80 -s 192.168.1.0/24 -j ACCEPT`",
                        "`sudo iptables -A INPUT -p tcp -j DROP`",
                        "",
                        "Save and Test Rules: Ensure the rules are correctly filtering traffic as expected.",
                    ].join('<br>')
                },
                {
                    title: "Exercise 4.5: Analyze and Secure SSH Traffic",
                    why: "Securing and monitoring SSH traffic is crucial for preventing unauthorized access and ensuring the confidentiality of the data transmitted.",
                    steps: [
                        "Capture SSH Packets: Use `tcpdump`:",
                        "`sudo tcpdump port 22 -i eth0 -w ssh_packets.pcap`",
                        "",
                        "Analyze Packets: Use tools like Wireshark to review the captured packets and check for anomalies or unencrypted data.",
                    ].join('<br>')
                },
                {
                    title: "Exercise 4.6: Set Up a Basic Web Server",
                    why: "A web server is essential for hosting websites and web applications.",
                    steps: [
                        "Install Web Server: For example, Apache:",
                        "`sudo apt-get install apache2  # On Ubuntu`",
                        "",
                        "Configure Server: Adjust settings in `/etc/apache2/apache2.conf`.",
                        "",
                        "Start and Verify:",
                        "`sudo systemctl start apache2`",
                        "`sudo systemctl status apache2`",
                        "",
                        "Test: Access the server using a web browser to ensure it serves content correctly.",
                    ].join('<br>')
                },
                {
                    title: "Exercise 4.7: Monitor System Performance with Netdata",
                    why: "Real-time performance monitoring allows for immediate detection of issues and helps in maintaining optimal system operation.",
                    steps: [
                        "Install Netdata:",
                        "`bash <(curl -Ss https://my-netdata.io/kickstart.sh)`",
                        "",
                        "Configure as Necessary: Adjust settings if specific monitoring configurations are needed.",
                        "",
                        "Access Netdata: View performance data by accessing `http://localhost:19999`.",
                    ].join('<br>')
                },
                {
                    title: "Exercise 4.8: Configure VPN Using OpenVPN",
                    why: "A VPN secures internet traffic, ensuring privacy and enabling remote access to network resources.",
                    steps: [
                        "Install OpenVPN:",
                        "`sudo apt-get install openvpn easy-rsa  # On Ubuntu`",
                        "",
                        "Configure VPN: Set up `/etc/openvpn/server.conf` and generate keys using Easy-RSA.",
                        "",
                        "Start VPN Service:",
                        "`sudo systemctl start openvpn@server`",
                        "",
                        "Test Connectivity: Ensure clients can connect and route traffic through the VPN.",
                    ].join('<br>')
                },
                {
                    title: "Exercise 4.9: Set Up and Monitor a Mail Server",
                    why: "A mail server handles the sending and receiving of emails for a domain.",
                    steps: [
                        "Install and Configure Postfix:",
                        "`sudo apt-get install postfix  # On Ubuntu`",
                        "",
                        "Adjust Settings: Configure `/etc/postfix/main.cf` for basic operations.",
                        "",
                        "Test Sending and Receiving Emails: Use mail or similar tools to send test emails.",
                    ].join('<br>')
                },
                {
                    title: "Exercise 4.10: Conduct a Security Audit with Lynis",
                    why: "Regular security audits help identify and mitigate potential vulnerabilities.",
                    steps: [
                        "Install Lynis:",
                        "`sudo apt-get install lynis  # On Ubuntu`",
                        "",
                        "Run Security Audit:",
                        "`sudo lynis audit system`",
                        "",
                        "Review Report: Analyze the output and follow recommendations to address security issues.",
                    ].join('<br>')
                }
            ]
        },
        {
            title: "Module 5: SSH and Remote Desktop",
            exercises: [
                {
                    title: "Exercise 5.1: Set Up SSH Key-Based Authentication",
                    why: "Key-based authentication is more secure than password-based authentication, reducing the risk of brute force attacks.",
                    steps: [
                        "Generate SSH Keys: On the client machine, generate a new SSH key pair:",
                        "`ssh-keygen -t rsa -b 4096`",
                        "",
                        "Copy Public Key to Server: Use `ssh-copy-id` to copy the public key to the server:",
                        "`ssh-copy-id user@server_ip`",
                        "",
                        "Test SSH Connection: Connect to the server without a password:",
                        "`ssh user@server_ip`",
                    ].join('<br>')
                },
                {
                    title: "Exercise 5.2: Configure OpenSSH Client",
                    why: "Customizing the SSH client configuration can simplify connections and enhance security.",
                    steps: [
                        "Edit SSH Client Configuration: Open `~/.ssh/config`:",
                        "`nano ~/.ssh/config`",
                        "",
                        "Set Host Alias and Default Username: Add configuration for a frequently accessed server:",
                        "`Host myserver`",
                        "`    HostName server_ip`",
                        "`    User myusername`",
                        "",
                        "Test Configuration: Connect using the alias:",
                        "`ssh myserver`",
                    ].join('<br>')
                },
                {
                    title: "Exercise 5.3: Secure OpenSSH Daemon",
                    why: "Securing the SSH daemon is crucial to prevent unauthorized access.",
                    steps: [
                        "Edit SSHD Configuration: Open `/etc/ssh/sshd_config`:",
                        "`sudo nano /etc/ssh/sshd_config`",
                        "",
                        "Disable Password Authentication: Ensure the file includes:",
                        "`PasswordAuthentication no`",
                        "",
                        "Restart SSH Service: Apply changes:",
                        "`sudo systemctl restart ssh`",
                    ].join('<br>')
                },
                {
                    title: "Exercise 5.4: Launch Remote X11 Application",
                    why: "Running GUI applications remotely can be useful for administrative tasks that require a graphical interface.",
                    steps: [
                        "Enable X11 Forwarding: On the server, edit `/etc/ssh/sshd_config` to include:",
                        "`X11Forwarding yes`",
                        "",
                        "Restart SSH Service:",
                        "`sudo systemctl restart ssh`",
                        "",
                        "Connect with X11 Forwarding Enabled: From the client:",
                        "`ssh -X user@server_ip`",
                        "",
                        "Run a GUI Application: For example, xeyes:",
                        "`xeyes`",
                    ].join('<br>')
                },
                {
                    title: "Exercise 5.5: Execute SSH Commands in Parallel",
                    why: "Executing commands in parallel across multiple systems can significantly speed up administrative tasks and deployments.",
                    steps: [
                        "Install Parallel-SSH: On the client machine:",
                        "`sudo apt install pssh  # On Ubuntu`",
                        "",
                        "Create a Hosts File: List all the servers' IPs you want to manage.",
                        "",
                        "Run a Command in Parallel: For example, checking uptime:",
                        "`parallel-ssh -h hosts.txt -P \"uptime\"`",
                    ].join('<br>')
                },
                {
                    title: "Exercise 5.6: Install and Test VNC Server",
                    why: "VNC provides a graphical desktop sharing system to remotely control another computer.",
                    steps: [
                        "Install VNC Server: For example, TightVNC:",
                        "`sudo apt install tightvncserver`",
                        "",
                        "Set Up VNC Server: Run vncserver and set a password.",
                        "",
                        "Connect Using a VNC Client: From another machine, connect to the server using the IP and display number.",
                    ].join('<br>')
                },
                {
                    title: "Exercise 5.7: Tunnel VNC Over SSH",
                    why: "Tunneling VNC over SSH enhances security by encrypting the VNC traffic.",
                    steps: [
                        "Set Up SSH Tunnel: From the client machine:",
                        "`ssh -L 5901:localhost:5901 user@server_ip -N`",
                        "",
                        "Connect Using VNC Client: Point to localhost:5901 instead of directly to the server.",
                    ].join('<br>')
                },
                {
                    title: "Exercise 5.8: Auto-start VNC Server",
                    why: "Ensuring VNC starts automatically at boot makes the system ready for remote administration without manual intervention.",
                    steps: [
                        "Create a systemd Service File: For VNC server:",
                        "`sudo nano /etc/systemd/system/vncserver@.service`",
                        "",
                        "Define Service Configuration: Example configuration:",
                        "`[Unit]`",
                        "`Description=Start VNC server at startup`",
                        "`After=syslog.target network.target`",
                        "",
                        "`[Service]`",
                        "`Type=forking`",
                        "`User=<USERNAME>`",
                        "`PAMName=login`",
                        "`PIDFile=/home/<USERNAME>/.vnc/%H:%i.pid`",
                        "`ExecStartPre=-/usr/bin/vncserver -kill :%i > /dev/null 2>&1`",
                        "`ExecStart=/usr/bin/vncserver :%i -geometry 1280x1024 -depth 24 -localhost no`",
                        "`ExecStop=/usr/bin/vncserver -kill :%i`",
                        "",
                        "`[Install]`",
                        "`WantedBy=multi-user.target`",
                        "",
                        "Enable and Start the Service:",
                        "`sudo systemctl enable vncserver@1`",
                        "`sudo systemctl start vncserver@1`",
                    ].join('<br>')
                },
                {
                    title: "Exercise 5.9: Configure Port Forwarding for SSH",
                    why: "Port forwarding via SSH (SSH tunneling) allows you to secure traffic to applications that might not inherently support encryption.",
                    steps: [
                        "Local Port Forwarding: To forward a local port to a remote server:",
                        "`ssh -L local_port:localhost:remote_port user@server_ip`",
                        "",
                        "Remote Port Forwarding: To allow remote clients to connect to a local service:",
                        "`ssh -R remote_port:localhost:local_port user@server_ip`",
                    ].join('<br>')
                },
                {
                    title: "Exercise 5.10: Harden SSH Configuration",
                    why: "Hardening SSH configuration enhances security against network attacks.",
                    steps: [
                        "Edit SSHD Configuration:",
                        "`sudo nano /etc/ssh/sshd_config`",
                        "",
                        "Change Settings: Such as disabling root login, changing the default port, and enabling only specific ciphers:",
                        "`PermitRootLogin no`",
                        "`Port 2222`",
                        "`Ciphers aes256-ctr,aes192-ctr,aes128-ctr`",
                        "",
                        "Restart SSH Service:",
                        "`sudo systemctl restart ssh`",
                    ].join('<br>')
                }
            ]
        }
        
    ];
    
    
    

    const contentDiv = document.getElementById('content');
    modules.forEach(module => {
        const moduleDiv = document.createElement('div');
        moduleDiv.className = 'module';
        const moduleTitle = document.createElement('h2');
        moduleTitle.textContent = module.title;
        moduleDiv.appendChild(moduleTitle);

        module.exercises.forEach(exercise => {
            const exerciseDiv = document.createElement('div');
            exerciseDiv.className = 'exercise';
            exerciseDiv.textContent = exercise.title;
            exerciseDiv.onclick = function () {
                solutionDiv.style.display = solutionDiv.style.display === 'none' ? 'block' : 'none';
            };

            const solutionDiv = document.createElement('div');
            solutionDiv.className = 'solution';
            solutionDiv.innerHTML = `<strong>Why:</strong> ${exercise.why}<br><strong>Steps:</strong><pre>${exercise.steps}</pre>`;

            exerciseDiv.appendChild(solutionDiv);
            moduleDiv.appendChild(exerciseDiv);
        });

        contentDiv.appendChild(moduleDiv);
    });
});
