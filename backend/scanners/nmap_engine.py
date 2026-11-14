import os
import re
import shlex
import shutil
import subprocess
import asyncio
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable


def is_admin() -> bool:
    """Checks whether the current process has administrator/root privileges."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        try:
            return os.geteuid() == 0
        except Exception:
            return False


# Known standard install locations
KNOWN_NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
]

# Risk and exposure profiles for well-known ports
RISK_PORT_INFO: Dict[int, Dict[str, Any]] = {
    135: {
        "title": "Esposizione MSRPC (Microsoft Remote Procedure Call)",
        "severity": "medium",
        "cvss": 6.5,
        "cwe_id": "CWE-200",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Discovery",
        "description": "L'endpoint RPC Microsoft (porta 135/TCP) è aperto e raggiungibile. Consente a utenti non autenticati o attaccanti di enumerare interfacce RPC di sistema, endpoint DCOM e informazioni sull'host.",
        "remediation": "Limitare l'accesso alla porta 135 via Windows Defender Firewall ed escludere l'ascolto su interfacce esposte a perimetri non fidati."
    },
    139: {
        "title": "Servizio NetBIOS Session Service Esposto (Porta 139)",
        "severity": "medium",
        "cvss": 5.8,
        "cwe_id": "CWE-200",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Discovery",
        "description": "Il servizio NetBIOS Session Service (porta 139/TCP) è attivo. Espone nomi di dominio/workgroup, interfacce e può facilitare enumerazione anonima degli utenti.",
        "remediation": "Disabilitare NetBIOS over TCP/IP nelle impostazioni di rete avanzate delle schede di rete e bloccare la porta 139 al perimetro."
    },
    445: {
        "title": "Servizio SMB Microsoft-DS (Porta 445) Esposto",
        "severity": "high",
        "cvss": 7.5,
        "cwe_id": "CWE-200",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021.002 - SMB/Windows Admin Shares",
        "description": "Il protocollo SMB è attivo sulla porta 445/TCP. Se esposto a segmenti non attendibili o privo di firma obbligatoria, presenta gravi rischi di attacchi NTLM Relay, brute force o exploit di esecuzione remota (es. MS17-010 EternalBlue).",
        "remediation": "Bloccare rigorosamente la porta 445 sul firewall perimetrale, abilitare SMB Signing obbligatorio e disabilitare il protocollo legacy SMBv1."
    },
    3389: {
        "title": "Servizio Microsoft Remote Desktop (RDP) Esposto",
        "severity": "medium",
        "cvss": 6.8,
        "cwe_id": "CWE-200",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078 - Valid Accounts",
        "description": "Porta RDP 3389 aperta sul sistema. Esposizione suscettibile a tentativi continui di brute-force, password spraying e vulnerabilità BlueKeep.",
        "remediation": "Non esporre mai RDP direttamente. Isolarlo dietro una VPN con autenticazione a due fattori (MFA) e abilitare Network Level Authentication (NLA)."
    },
    21: {
        "title": "Servizio FTP (Porta 21) Esposto in Chiaro",
        "severity": "medium",
        "cvss": 7.0,
        "cwe_id": "CWE-319",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078 - Valid Accounts",
        "description": "Il servizio FTP tradizionale trasmette comandi, password e file in chiaro sulla rete senza crittografia.",
        "remediation": "Disabilitare FTP non cifrato e migrare a SFTP (SSH File Transfer Protocol) o FTPS (FTP over TLS/SSL)."
    },
    23: {
        "title": "Protocollo Telnet Esposto Senza Crittografia (Porta 23)",
        "severity": "high",
        "cvss": 8.5,
        "cwe_id": "CWE-319",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078 - Valid Accounts",
        "description": "Il servizio Telnet trasmette credenziali amministrative e comunicazioni interamente in chiaro.",
        "remediation": "Disattivare immediatamente Telnet e utilizzare esclusivamente SSH v2 cifrato."
    },
    3306: {
        "title": "Database MySQL / MariaDB Esposto sulla Rete (Porta 3306)",
        "severity": "medium",
        "cvss": 7.0,
        "cwe_id": "CWE-306",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "description": "Il database MySQL/MariaDB accetta connessioni remote sulla porta 3306. Espone il database ad attacchi di password spraying o exploit.",
        "remediation": "Configurare bind-address = 127.0.0.1 in my.cnf o limitare l'accesso con firewall solo agli application server autorizzati."
    },
    5432: {
        "title": "Database PostgreSQL Esposto sulla Rete (Porta 5432)",
        "severity": "medium",
        "cvss": 7.0,
        "cwe_id": "CWE-306",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "description": "Il server PostgreSQL è raggiungibile sulla porta 5432/TCP.",
        "remediation": "Restringere listen_addresses in postgresql.conf e limitare l'accesso nel file pg_hba.conf ai soli IP fidati."
    },
    6379: {
        "title": "Database In-Memory Redis Esposto (Porta 6379)",
        "severity": "high",
        "cvss": 8.5,
        "cwe_id": "CWE-306",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1552 - Unsecured Credentials",
        "description": "Istanza Redis raggiungibile sulla porta 6379. Se non protetta da password robusta, permette dump immediato della memoria e potenziale RCE.",
        "remediation": "Impostare 'requirepass' robusto in redis.conf ed eseguire il binding unicamente sull'interfaccia di loopback (127.0.0.1)."
    },
    27017: {
        "title": "Database NoSQL MongoDB Esposto (Porta 27017)",
        "severity": "high",
        "cvss": 7.5,
        "cwe_id": "CWE-306",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1552 - Unsecured Credentials",
        "description": "Porta MongoDB 27017 aperta e raggiungibile dall'esterno. Rischio di accesso non autorizzato e data exfiltration.",
        "remediation": "Abilitare security.authorization in mongod.conf e limitare l'accesso solo agli IP autorizzati."
    },
    5985: {
        "title": "Interfaccia Windows Remote Management WinRM HTTP (Porta 5985)",
        "severity": "medium",
        "cvss": 6.5,
        "cwe_id": "CWE-200",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021.006 - Windows Remote Management",
        "description": "Il servizio WinRM HTTP è in ascolto sulla porta 5985/TCP. Consente l'esecuzione remota di comandi PowerShell e WMI su Windows.",
        "remediation": "Disabilitare WinRM HTTP non cifrato sui perimetri non gestiti, forzare l'uso di WinRM HTTPS (porta 5986) con certificati attendibili e limitare l'accesso via firewall."
    },
    554: {
        "title": "Servizio Streaming Video RTSP Esposto (Porta 554 - IP Camera / Media)",
        "severity": "medium",
        "cvss": 5.8,
        "cwe_id": "CWE-319",
        "mitre_tactic": "Collection",
        "mitre_technique": "T1125 - Video Capture",
        "description": "Il protocollo Real Time Streaming Protocol (RTSP, porta 554/TCP) è attivo sull'host (tipico di telecamere IP, NVR o media server). Se non autenticato o configurato con credenziali di default, permette l'intercettazione dei flussi video/audio in chiaro.",
        "remediation": "Impostare credenziali RTSP robuste non predefinite, disabilitare l'accesso anonimo al flusso video e isolare le telecamere IP/dispositivi multimediali su una VLAN IoT dedicata."
    },
    8008: {
        "title": "Interfaccia di Controllo HTTP Alternativa / Smart Cast Esposta (Porta 8008)",
        "severity": "low",
        "cvss": 4.3,
        "cwe_id": "CWE-200",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Discovery",
        "description": "La porta 8008/TCP (HTTP-Alt / Google Cast / Smart Display API) è aperta sulla LAN. Consente a qualsiasi client sullo stesso segmento di rete di interrogare informazioni sul dispositivo, stato multimediale e configurazione locale senza autenticazione.",
        "remediation": "Isolare i dispositivi Smart Home, Cast e speaker su una VLAN IoT separata dalla rete delle workstation aziendali o personali critiche."
    },
    8009: {
        "title": "Protocollo AJP13 / Cast TLS Control Channel Esposto (Porta 8009)",
        "severity": "low",
        "cvss": 4.3,
        "cwe_id": "CWE-200",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Discovery",
        "description": "La porta 8009/TCP è attiva (utilizzata da Google Cast control channel su TLS oppure dal connettore Apache JServ Protocol AJP13). Permette il controllo remoto del dispositivo multimediale o la comunicazione diretta con il backend applicativo.",
        "remediation": "Se si tratta di un dispositivo Smart/Cast, segregarlo su VLAN IoT; se si tratta di Apache Tomcat AJP13, disabilitare il connettore o proteggerlo con 'secretRequired=true' (mitigazione Ghostcat CVE-2020-1938)."
    },
    5357: {
        "title": "Servizio Microsoft WSDAPI (Web Services for Devices - Porta 5357) Esposto",
        "severity": "low",
        "cvss": 3.7,
        "cwe_id": "CWE-200",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Discovery",
        "description": "Il servizio Web Services on Devices (WSDAPI, porta 5357/TCP) è attivo. Viene impiegato da Windows e stampanti di rete per il discovery automatico e la condivisione risorse, esponendo metadati hardware sull'host.",
        "remediation": "Disabilitare l'individuazione della rete (Network Discovery) sui profili firewall non fidati o bloccare la porta 5357/TCP."
    },
    53: {
        "title": "Servizio Risolutore / Server DNS Esposto (Porta 53/TCP)",
        "severity": "low",
        "cvss": 3.5,
        "cwe_id": "CWE-200",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1018 - Remote System Discovery",
        "description": "Il servizio DNS risponde sulla porta 53/TCP (tipico di gateway/router o domain controller). Consente l'enumerazione dei record DNS locali e la risoluzione di nomi host interni.",
        "remediation": "Disabilitare i trasferimenti di zona DNS (AXFR) non autorizzati e limitare le query ricorsive ai soli client della subnet interna."
    }
}


# Curated catalog of essential Purple Team NSE scripts
CURATED_NSE_SCRIPTS = [
    {
        "id": "http-vuln-cve2021-41773",
        "name": "Apache Path Traversal & RCE (CVE-2021-41773)",
        "categories": ["vuln", "exploit"],
        "severity": "critical",
        "cvss": 9.8,
        "cve": "CVE-2021-41773",
        "description": "Verifica se Apache HTTP Server 2.4.49 è vulnerabile a Path Traversal o RCE tramite caratteri codificati.",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application"
    },
    {
        "id": "http-sql-injection",
        "name": "HTTP SQL Injection Detector",
        "categories": ["vuln", "intrusive"],
        "severity": "high",
        "cvss": 8.5,
        "cve": "",
        "description": "Inietta payload SQLi controllati per identificare parametri vulnerabili a SQL Injection.",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application"
    },
    {
        "id": "http-stored-xss",
        "name": "HTTP Stored XSS Detector",
        "categories": ["vuln", "intrusive"],
        "severity": "medium",
        "cvss": 6.1,
        "cve": "",
        "description": "Cerca campi input vulnerabili a Stored Cross-Site Scripting (XSS).",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1189 - Drive-by Compromise"
    },
    {
        "id": "http-csrf",
        "name": "HTTP Cross-Site Request Forgery Detector",
        "categories": ["vuln", "safe"],
        "severity": "medium",
        "cvss": 6.5,
        "cve": "",
        "description": "Rileva form HTML privi di token anti-CSRF.",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1189 - Drive-by Compromise"
    },
    {
        "id": "http-security-headers",
        "name": "HTTP Security Headers Audit",
        "categories": ["discovery", "safe"],
        "severity": "low",
        "cvss": 4.3,
        "cve": "",
        "description": "Verifica l'assenza di CSP, HSTS, X-Frame-Options e altri header di protezione.",
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1592 - Gather Victim Host Information"
    },
    {
        "id": "http-enum",
        "name": "HTTP Directory & Application Enumeration",
        "categories": ["discovery", "safe"],
        "severity": "info",
        "cvss": 0.0,
        "cve": "",
        "description": "Enumera file e cartelle comuni, CMS, console di amministrazione e backup web.",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1083 - File and Directory Discovery"
    },
    {
        "id": "http-title",
        "name": "HTTP Title Grabber",
        "categories": ["discovery", "safe"],
        "severity": "info",
        "cvss": 0.0,
        "cve": "",
        "description": "Estrae il tag <title> delle pagine web esposte per categorizzare il servizio.",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Discovery"
    },
    {
        "id": "http-methods",
        "name": "HTTP Dangerous Methods Check",
        "categories": ["default", "safe"],
        "severity": "medium",
        "cvss": 5.3,
        "cve": "",
        "description": "Identifica metodi HTTP pericolosi abilitati (PUT, DELETE, TRACE).",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application"
    },
    {
        "id": "ssl-cert",
        "name": "SSL/TLS Certificate Inspection",
        "categories": ["default", "safe", "discovery"],
        "severity": "low",
        "cvss": 3.7,
        "cve": "",
        "description": "Recupera e valida il certificato X.509 del server (validità, SAN, emittente, scadenza).",
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1592 - Gather Victim Host Information"
    },
    {
        "id": "ssl-enum-ciphers",
        "name": "SSL/TLS Ciphers & Protocol Audit",
        "categories": ["discovery", "safe"],
        "severity": "medium",
        "cvss": 5.9,
        "cve": "",
        "description": "Enumera i protocolli TLS abilitati (TLS 1.0/1.1/1.2/1.3) e le cipher suite deboli (RC4, DES).",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1573 - Encrypted Channel"
    },
    {
        "id": "ssl-heartbleed",
        "name": "OpenSSL Heartbleed Bug (CVE-2014-0160)",
        "categories": ["vuln", "safe"],
        "severity": "critical",
        "cvss": 7.5,
        "cve": "CVE-2014-0160",
        "description": "Controlla la vulnerabilità Heartbleed che consente il leak della memoria privata TLS.",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1552 - Unsecured Credentials"
    },
    {
        "id": "ssl-poodle",
        "name": "SSLv3 POODLE Vulnerability (CVE-2014-3566)",
        "categories": ["vuln", "safe"],
        "severity": "medium",
        "cvss": 4.3,
        "cve": "CVE-2014-3566",
        "description": "Verifica se il server supporta SSLv3 affetto da attacco POODLE.",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1573 - Encrypted Channel"
    },
    {
        "id": "smb-vuln-ms17-010",
        "name": "SMB EternalBlue Remote Code Execution (MS17-010)",
        "categories": ["vuln", "safe"],
        "severity": "critical",
        "cvss": 9.8,
        "cve": "CVE-2017-0143",
        "description": "Verifica la vulnerabilità critica EternalBlue utilizzata da WannaCry e NotPetya.",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1210 - Exploitation of Remote Services"
    },
    {
        "id": "smb-os-discovery",
        "name": "SMB OS & Domain Discovery",
        "categories": ["default", "safe", "discovery"],
        "severity": "info",
        "cvss": 0.0,
        "cve": "",
        "description": "Raccoglie sistema operativo, nome del dominio, hostname NetBIOS e ora di sistema via SMB.",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1018 - Remote System Discovery"
    },
    {
        "id": "smb-enum-shares",
        "name": "SMB Shares Enumeration",
        "categories": ["discovery", "safe"],
        "severity": "medium",
        "cvss": 5.0,
        "cve": "",
        "description": "Elenca le cartelle condivise Windows accessibili pubblicamente o con credenziali anonime.",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1135 - Network Share Discovery"
    },
    {
        "id": "smb2-security-mode",
        "name": "SMBv2 Security Mode & Signing Audit",
        "categories": ["default", "safe"],
        "severity": "high",
        "cvss": 7.4,
        "cve": "",
        "description": "Rileva se la firma SMB (SMB Signing) è abilitata ma non richiesta (rischio NTLM relay).",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1557.001 - LLMNR/NBT-NS Poisoning and Relay"
    },
    {
        "id": "ssh-auth-methods",
        "name": "SSH Supported Authentication Methods",
        "categories": ["default", "safe"],
        "severity": "low",
        "cvss": 3.0,
        "cve": "",
        "description": "Enumera i metodi di autenticazione consentiti dal demone SSH (password, publickey).",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078 - Valid Accounts"
    },
    {
        "id": "ssh2-enum-algos",
        "name": "SSH2 Key Exchange & Ciphers Audit",
        "categories": ["safe", "discovery"],
        "severity": "low",
        "cvss": 3.7,
        "cve": "",
        "description": "Segnala algoritmi crittografici obsoleti (3DES, arcfour, diffie-hellman-group1-sha1) su SSH.",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1573 - Encrypted Channel"
    },
    {
        "id": "ftp-anon",
        "name": "Anonymous FTP Login Allowed",
        "categories": ["default", "auth", "safe"],
        "severity": "high",
        "cvss": 7.5,
        "cve": "",
        "description": "Verifica se il server FTP accetta login anonimo ('anonymous' / password vuota).",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078 - Valid Accounts"
    },
    {
        "id": "ftp-vsftpd-backdoor",
        "name": "vsftpd 2.3.4 Smiley Face Backdoor (CVE-2011-2523)",
        "categories": ["vuln", "exploit"],
        "severity": "critical",
        "cvss": 9.8,
        "cve": "CVE-2011-2523",
        "description": "Verifica la presenza della storica backdoor vsftpd 2.3.4 (apre shell su porta 6200).",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059 - Command and Scripting Interpreter"
    },
    {
        "id": "dns-zone-transfer",
        "name": "DNS Zone Transfer (AXFR)",
        "categories": ["discovery", "safe"],
        "severity": "high",
        "cvss": 7.5,
        "cve": "",
        "description": "Tenta il trasferimento di zona completo (AXFR) su server DNS non configurati correttamente.",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1590.002 - DNS"
    },
    {
        "id": "dns-recursion",
        "name": "DNS Open Recursion Resolver Check",
        "categories": ["default", "safe"],
        "severity": "medium",
        "cvss": 5.3,
        "cve": "",
        "description": "Identifica resolver DNS aperti utilizzabili per attacchi di amplificazione DDoS.",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1498 - Network Denial of Service"
    },
    {
        "id": "rdp-enum-encryption",
        "name": "RDP Encryption & NLA Audit",
        "categories": ["safe", "discovery"],
        "severity": "medium",
        "cvss": 5.0,
        "cve": "",
        "description": "Verifica se RDP richiede Network Level Authentication (NLA) o usa cifratura debole.",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078 - Valid Accounts"
    },
    {
        "id": "rdp-vuln-ms12-020",
        "name": "MS12-020 RDP Denial of Service / RCE",
        "categories": ["vuln", "safe"],
        "severity": "high",
        "cvss": 8.5,
        "cve": "CVE-2012-0002",
        "description": "Rileva sistemi RDP vulnerabili a pacchetti malformati MS12-020.",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499 - Endpoint Denial of Service"
    },
    {
        "id": "mysql-empty-password",
        "name": "MySQL Root Empty Password Check",
        "categories": ["auth", "safe"],
        "severity": "critical",
        "cvss": 9.8,
        "cve": "",
        "description": "Controlla se l'account root o anonimo di MySQL è accessibile senza password.",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078 - Valid Accounts"
    },
    {
        "id": "redis-info",
        "name": "Redis Information & Exposure Audit",
        "categories": ["discovery", "safe"],
        "severity": "high",
        "cvss": 8.0,
        "cve": "",
        "description": "Interroga Redis per estrarre statistiche INFO e verificare l'assenza di autenticazione.",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Discovery"
    },
    {
        "id": "mongodb-info",
        "name": "MongoDB Unauthenticated Info Dump",
        "categories": ["discovery", "safe"],
        "severity": "high",
        "cvss": 8.0,
        "cve": "",
        "description": "Rileva istanze MongoDB esposte senza autenticazione ed elenca i database.",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1552 - Unsecured Credentials"
    },
    {
        "id": "snmp-info",
        "name": "SNMP Information & Community String Grabber",
        "categories": ["default", "discovery", "safe"],
        "severity": "medium",
        "cvss": 5.0,
        "cve": "",
        "description": "Estrae informazioni hardware, interfacce e routing usando community string pubbliche (public).",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1018 - Remote System Discovery"
    },
    {
        "id": "vulners",
        "name": "Vulners CVE Lookup Engine",
        "categories": ["vuln", "safe"],
        "severity": "high",
        "cvss": 7.5,
        "cve": "",
        "description": "Correlazione automatica delle versioni dei software rilevati con il database Vulners CVE.",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Discovery"
    },
    {
        "id": "banner",
        "name": "Service Banner Grabber",
        "categories": ["discovery", "safe"],
        "severity": "info",
        "cvss": 0.0,
        "cve": "",
        "description": "Cattura l'header o il banner inviato dal servizio subito dopo la connessione TCP.",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Discovery"
    }
]

ZENMAP_PRESETS = [
    {
        "id": "quick_discovery",
        "name": "Quick Port & Host Discovery",
        "description": "Scansione rapida TCP top-100 porte e rilevamento base servizi.",
        "flags": ["-sT", "-F", "--version-light", "-T4"],
        "recommended_for": "Inventario immediato e perimetri ampi."
    },
    {
        "id": "full_purple",
        "name": "Full Purple Team Assessment",
        "description": "Scansione TCP completa, service banner grabbing, OS detection e script standard.",
        "flags": ["-sT", "-sV", "-sC", "--version-all", "-O", "-T4"],
        "recommended_for": "Audit approfondito perimetrale o interno."
    },
    {
        "id": "nse_vuln_sweep",
        "name": "NSE Vulnerability & CVE Sweep",
        "description": "Esegue tutti gli script NSE della categoria 'vuln' per rilevare exploit noti.",
        "flags": ["-sT", "-sV", "--script", "vuln", "-T3"],
        "recommended_for": "Verifica CVE perimetrali ed exploit critici."
    },
    {
        "id": "web_ssl_audit",
        "name": "Web & TLS/SSL Audit",
        "description": "Targettizzato sulle porte HTTP/HTTPS (80, 443, 8080, 8443) con script SSL e Web.",
        "flags": ["-sT", "-p", "80,443,8000,8080,8443,9000", "--script", "http-security-headers,http-methods,ssl-cert,ssl-enum-ciphers,ssl-heartbleed"],
        "recommended_for": "Applicazioni web ed API gateway."
    },
    {
        "id": "smb_infra_audit",
        "name": "Internal Infrastructure & Active Directory SMB",
        "description": "Ispezione porte Active Directory, SMB, RDP (135, 139, 445, 3389) con script di audit sicurezza.",
        "flags": ["-sT", "-p", "135,139,445,3389", "--script", "smb-os-discovery,smb2-security-mode,smb-enum-shares,smb-vuln-ms17-010,rdp-enum-encryption"],
        "recommended_for": "Segmenti LAN aziendali e controller di dominio."
    },
    {
        "id": "stealth_syn",
        "name": "Stealth Low & Slow Scan",
        "description": "Scansione a bassa intensità per ridurre il rumore su IDS/SIEM.",
        "flags": ["-sT", "-T2", "--randomize-hosts"],
        "recommended_for": "Scansioni silenziose o test di rilevamento SOC."
    }
]


def detect_nmap() -> Dict[str, Any]:
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        for p in KNOWN_NMAP_PATHS:
            if os.path.isfile(p):
                nmap_path = p
                break

    if not nmap_path:
        return {
            "installed": False,
            "version": "",
            "path": "",
            "scripts_dir": "",
            "nse_count": 0
        }

    version = "Unknown"
    try:
        proc = subprocess.run([nmap_path, "--version"], capture_output=True, text=True, timeout=5)
        m = re.search(r"Nmap version ([0-9\.]+)", proc.stdout)
        if m:
            version = m.group(1)
        else:
            version = proc.stdout.splitlines()[0] if proc.stdout else "Available"
    except Exception:
        pass

    # Locate scripts folder
    scripts_dir = ""
    nse_count = 0
    parent_dir = Path(nmap_path).parent
    possible_scripts = [
        parent_dir / "scripts",
        parent_dir / "share" / "nmap" / "scripts",
        Path("/usr/share/nmap/scripts"),
    ]
    for sdir in possible_scripts:
        if sdir.is_dir():
            scripts_dir = str(sdir)
            try:
                nse_files = list(sdir.glob("*.nse"))
                nse_count = len(nse_files)
            except Exception:
                pass
            break

    return {
        "installed": True,
        "version": version,
        "path": nmap_path,
        "scripts_dir": scripts_dir,
        "nse_count": nse_count
    }


def get_nse_catalog(category: Optional[str] = None, search: Optional[str] = None) -> Dict[str, Any]:
    detection = detect_nmap()
    items = list(CURATED_NSE_SCRIPTS)

    # If scripts_dir exists, enrich with filenames not in curated
    if detection["installed"] and detection["scripts_dir"]:
        sdir = Path(detection["scripts_dir"])
        curated_ids = {item["id"] for item in items}
        try:
            for f in sdir.glob("*.nse"):
                script_id = f.stem
                if script_id not in curated_ids:
                    items.append({
                        "id": script_id,
                        "name": script_id.replace("-", " ").title(),
                        "categories": ["discovery"],
                        "severity": "info",
                        "cvss": 0.0,
                        "cve": "",
                        "description": f"Script NSE ufficiale Nmap ({f.name}) disponibile sul disco.",
                        "mitre_tactic": "Discovery",
                        "mitre_technique": "T1046 - Network Service Discovery"
                    })
        except Exception:
            pass

    # Filtering
    if category and category != "all":
        items = [i for i in items if category.lower() in [c.lower() for c in i.get("categories", [])]]

    if search:
        q = search.lower()
        items = [
            i for i in items
            if q in i["id"].lower() or q in i["name"].lower() or q in i.get("description", "").lower()
        ]

    return {
        "total": len(items),
        "scripts": items,
        "presets": ZENMAP_PRESETS,
        "nmap_info": detection
    }


async def run_nmap_scan(
    targets: str,
    ports: Optional[str] = None,
    nmap_flags: Optional[Any] = None,
    nse_scripts: Optional[List[str]] = None,
    log_callback: Optional[Callable[[str, str], Any]] = None
) -> Dict[str, Any]:
    detection = detect_nmap()
    if not detection["installed"]:
        raise RuntimeError("Nmap non è installato sul sistema o non è raggiungibile.")

    def log(level: str, msg: str):
        if log_callback:
            try:
                res = log_callback(level, msg)
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)
            except Exception:
                pass

    admin = is_admin()
    if not admin:
        log("INFO", "[Nmap Engine] Processo in esecuzione senza privilegi Administrator/Root.")

    # Parse nmap_flags (which can be a string, a list of strings, or None)
    raw_tokens: List[str] = []
    if nmap_flags:
        if isinstance(nmap_flags, str):
            raw_tokens = shlex.split(nmap_flags)
        elif isinstance(nmap_flags, list):
            for item in nmap_flags:
                if isinstance(item, str):
                    raw_tokens.extend(shlex.split(item))
                else:
                    raw_tokens.append(str(item))
    else:
        raw_tokens = ["-sT", "-sV", "-T4"]

    clean_flags: List[str] = []
    has_syn = False
    has_connect = False
    has_pn = False

    ALLOWED_SINGLE_FLAGS = {"-sV", "-sC", "-sT", "-Pn", "-P0", "-F", "-v", "-vv", "-n", "--open", "--version-light", "--randomize-hosts", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5"}
    for token in raw_tokens:
        tok = token.strip()
        if not tok or tok.lower() in ["nmap", "nmap.exe", "-ox", "-"]:
            continue
        if tok == "-sS":
            has_syn = True
            if not admin:
                log("INFO", "[Nmap Engine] Flag -sS convertito in -sT (privilegi Administrator non rilevati).")
                if "-sT" not in clean_flags:
                    clean_flags.append("-sT")
                has_connect = True
            else:
                clean_flags.append("-sS")
        elif tok == "-sT":
            has_connect = True
            if "-sT" not in clean_flags:
                clean_flags.append("-sT")
        elif tok == "-O":
            if not admin:
                log("INFO", "[Nmap Engine] Flag -O rimosso (OS detection richiede privilegi Administrator su Windows).")
            else:
                clean_flags.append("-O")
        elif tok.startswith("-Pn") or tok == "-P0":
            has_pn = True
            if "-Pn" not in clean_flags:
                clean_flags.append("-Pn")
        elif tok in ALLOWED_SINGLE_FLAGS:
            if tok not in clean_flags:
                clean_flags.append(tok)

    if not has_syn and not has_connect:
        clean_flags.insert(0, "-sT")

    # Always ensure -Pn is present to bypass Windows ICMP firewall blocks
    if not has_pn:
        clean_flags.append("-Pn")

    # Target arguments: preserve CIDR (/24) and IP ranges, strip URL schemes/paths/ports safely
    raw_entries = [t.strip() for t in targets.replace(",", " ").split() if t.strip()]
    raw_targets: List[str] = []
    extra_ports: List[str] = []
    has_subnet_or_range = False

    for entry in raw_entries:
        is_url = bool(re.match(r"^https?://", entry, flags=re.IGNORECASE))
        cleaned = re.sub(r"^https?://", "", entry, flags=re.IGNORECASE)
        if is_url:
            cleaned = cleaned.split("/")[0]
        else:
            # Check if "/" is a CIDR prefix (e.g. 192.168.1.0/24) vs URL path
            if "/" in cleaned:
                base_part, slash_part = cleaned.split("/", 1)
                if slash_part.isdigit() and 0 <= int(slash_part) <= 128:
                    cleaned = f"{base_part}/{slash_part}"
                    has_subnet_or_range = True
                else:
                    cleaned = base_part
            elif re.match(r"^\d+\.\d+\.\d+\.\d+-\d+$", cleaned):
                has_subnet_or_range = True

        if ":" in cleaned and not cleaned.startswith("[") and "/" not in cleaned:
            host_part, port_part = cleaned.rsplit(":", 1)
            if port_part.isdigit():
                extra_ports.append(port_part)
            cleaned = host_part
        if cleaned and cleaned not in raw_targets:
            raw_targets.append(cleaned)

    if not raw_targets:
        raise ValueError("Nessun target specificato per la scansione Nmap.")

    nmap_bin = detection["path"]

    # 2-Stage Smart Subnet Discovery: if scanning a CIDR subnet (/24) or range,
    # run fast ARP/ICMP Host Discovery (-sn) first so we don't waste 15 minutes port-scanning 240 dead IPs!
    discovered_hosts_meta: Dict[str, Dict[str, str]] = {}
    if has_subnet_or_range:
        sn_args = [nmap_bin, "-sn", "-oX", "-"] + raw_targets
        log("INFO", f"[Nmap Subnet Discovery] Ricerca host attivi sulla rete ({', '.join(raw_targets)})...")
        try:
            sn_proc = await asyncio.create_subprocess_exec(
                *sn_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            sn_out, _ = await sn_proc.communicate()
            sn_xml = sn_out.decode("utf-8", errors="replace")
            sn_hosts, _ = parse_nmap_xml(sn_xml, None)
            if sn_hosts:
                for sh in sn_hosts:
                    discovered_hosts_meta[sh["ip"]] = {
                        "hostname": sh.get("hostname", sh["ip"]),
                        "os": sh.get("os", "Network Host"),
                        "mac": sh.get("mac", ""),
                        "vendor": sh.get("vendor", "")
                    }
                live_ips = list(discovered_hosts_meta.keys())
                log("INFO", f"[Nmap Subnet Discovery] Rilevati {len(live_ips)} host attivi: {', '.join(live_ips)}")
                raw_targets = live_ips
            else:
                log("WARN", "[Nmap Subnet Discovery] Nessun host ha risposto al ping discovery; proseguo sulla subnet.")
        except Exception as e:
            log("WARN", f"[Nmap Subnet Discovery] Errore durante discovery preliminare: {str(e)}")

    # If we are scanning multiple hosts (e.g. a LAN subnet), optimize flags so it completes quickly and reliably
    is_full_port_range = str(ports) in ["all", "1-65535"]
    if len(raw_targets) > 3 or has_subnet_or_range:
        # On multi-host LAN scans, heavy -sV and NSE scripts on every port slow down Nmap 10x;
        # use fast TCP port discovery + service detection light
        if "-sV" in clean_flags and len(raw_targets) > 5:
            clean_flags.remove("-sV")
        if is_full_port_range and len(raw_targets) > 3:
            # 65,535 ports cannot finish in 25s at 250 pps! Use higher rate & generous timeout
            if "-sC" in clean_flags:
                clean_flags.remove("-sC")
            if "--min-rate" not in clean_flags:
                clean_flags.extend(["--min-rate", "1500", "--max-retries", "1", "--host-timeout", "180s"])
            if nse_scripts and len(raw_targets) > 5:
                log("INFO", "[Nmap Engine] Scansione full-port (-p-) su più host: script NSE limitati per evitare timeout.")
                nse_scripts = []
        else:
            if "--min-rate" not in clean_flags:
                clean_flags.extend(["--min-rate", "250", "--max-retries", "1", "--host-timeout", "35s"])
            if len(raw_targets) > 5 and nse_scripts == ["banner"]:
                nse_scripts = []

    args = [nmap_bin, "-oX", "-"]
    args.extend(clean_flags)

    # Ports
    if ports:
        if ports == "top-100":
            if "-F" not in args:
                args.extend(["-F"])
        elif ports == "top-1000":
            if len(raw_targets) > 5 and "-F" not in args:
                args.extend(["-F"])  # Top 100 fast scan when scanning 6+ LAN hosts
        elif ports in ["all", "1-65535"]:
            if "-p-" not in args:
                args.extend(["-p-"])
        else:
            port_str = str(ports)
            for ep in extra_ports:
                if ep not in port_str.split(","):
                    port_str += f",{ep}"
            if "-p" not in args:
                args.extend(["-p", port_str])

    # NSE scripts
    if nse_scripts and len(nse_scripts) > 0:
        if "--script" not in args:
            args.extend(["--script", ",".join(nse_scripts)])

    args.extend(raw_targets)

    cmd_str = " ".join(args)
    log("INFO", f"Avvio esecuzione Nmap: {cmd_str}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
    except Exception as e:
        log("ERROR", f"Errore durante l'esecuzione del processo Nmap: {str(e)}")
        raise

    xml_output = stdout.decode("utf-8", errors="replace")
    err_output = stderr.decode("utf-8", errors="replace")

    if err_output:
        log("WARN", f"Messaggio da Nmap stderr: {err_output[:300]}")

    hosts, findings = parse_nmap_xml(xml_output, log_callback)

    # Merge any hosts found in Stage 1 (-sn) that might have timed out in Stage 2
    existing_ips = {h["ip"]: h for h in hosts}
    for dip, dmeta in discovered_hosts_meta.items():
        if dip not in existing_ips:
            hosts.append({
                "ip": dip,
                "hostname": dmeta.get("hostname", dip),
                "os": dmeta.get("os", "Network Host"),
                "mac": dmeta.get("mac", ""),
                "vendor": dmeta.get("vendor", ""),
                "ports": []
            })
        else:
            h_obj = existing_ips[dip]
            if (not h_obj.get("hostname") or h_obj["hostname"] == dip) and dmeta.get("hostname"):
                h_obj["hostname"] = dmeta["hostname"]
            if h_obj.get("os") in [None, "", "Indeterminato / Non rilevato"] and dmeta.get("os"):
                h_obj["os"] = dmeta["os"]

    # For multi-host/subnet scans, also add an Asset & MAC Inventory finding for hosts with 0 open ports
    # so every live device (IoT, smart plug, mobile, appliance) appears in the scan findings as well as Host Topology
    finding_hosts = {f["host"] for f in findings}
    for h in hosts:
        hip = h["ip"]
        if hip not in finding_hosts and len(h.get("ports", [])) == 0:
            hname = h.get("hostname") or hip
            hos = h.get("os") or "Host Attivo"
            findings.append({
                "host": hip,
                "port": 0,
                "protocol": "arp/icmp",
                "service": "host-discovery",
                "title": f"Asset di Rete Attivo Rilevato: {hname} ({hos})",
                "severity": "info",
                "cvss": 0.0,
                "cve_ids": "",
                "cwe_id": "CWE-200",
                "source_engine": "nmap",
                "description": f"Il dispositivo {hip} ({hname}) ha risposto al discovery ARP/ICMP sulla subnet locale. Tutte le 100 porte TCP standard risultano chiuse o filtrate da firewall.",
                "evidence": f"IP: {hip}\nHostname: {hname}\nFingerprint Hardware/OS: {hos}\nStato Porte TCP: 100 filtered/closed",
                "remediation": "Verificare che il dispositivo sia censito nell'inventario degli asset autorizzati (CMDB) e che risieda nella VLAN corretta (es. separazione VLAN IoT/Guest).",
                "mitre_tactic": "Discovery",
                "mitre_technique": "T1018 - Remote System Discovery",
                "ai_insight": f"Dispositivo attivo identificato sulla LAN ({hos})."
            })

    log("INFO", f"Nmap terminato con successo. Host rilevati: {len(hosts)}, Finding estratti: {len(findings)}")

    return {
        "hosts": hosts,
        "findings": findings,
        "raw_xml": xml_output,
        "command": cmd_str
    }


def parse_nmap_xml(xml_data: str, log_callback: Optional[Callable[[str, str], Any]] = None) -> (List[Dict[str, Any]], List[Dict[str, Any]]):
    hosts = []
    findings = []

    if not xml_data.strip():
        return hosts, findings

    try:
        root = ET.fromstring(xml_data)
    except Exception:
        return hosts, findings

    for host_el in root.findall("host"):
        # Status
        status_el = host_el.find("status")
        state = status_el.get("state") if status_el is not None else "unknown"
        if state != "up":
            continue

        # IP addresses, MAC & hostnames
        ip_addr = ""
        mac_addr = ""
        mac_vendor = ""
        for addr in host_el.findall("address"):
            atype = addr.get("addrtype")
            if atype in ["ipv4", "ipv6"] and not ip_addr:
                ip_addr = addr.get("addr", "")
            elif atype == "mac":
                mac_addr = addr.get("addr", "")
                mac_vendor = addr.get("vendor", "")

        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        # OS detection
        os_name = "Indeterminato / Non rilevato"
        os_el = host_el.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", os_name)

        if os_name == "Indeterminato / Non rilevato" and (mac_vendor or mac_addr):
            if mac_vendor and mac_addr:
                os_name = f"{mac_vendor} (MAC: {mac_addr})"
            elif mac_vendor:
                os_name = mac_vendor
            else:
                os_name = f"MAC: {mac_addr}"

        host_dict = {
            "ip": ip_addr or "0.0.0.0",
            "hostname": hostname or ip_addr,
            "os": os_name,
            "mac": mac_addr,
            "vendor": mac_vendor,
            "ports": []
        }

        # Ports
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_id = int(port_el.get("portid", 0))
                proto = port_el.get("protocol", "tcp")

                pst_el = port_el.find("state")
                pstate = pst_el.get("state") if pst_el is not None else "closed"
                if pstate != "open":
                    continue

                svc_el = port_el.find("service")
                svc_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""
                extrainfo = svc_el.get("extrainfo", "") if svc_el is not None else ""

                full_prod = f"{product} {version}".strip()
                if extrainfo:
                    full_prod += f" ({extrainfo})"

                host_dict["ports"].append({
                    "port": port_id,
                    "protocol": proto,
                    "service": svc_name,
                    "product": full_prod or svc_name,
                    "version": version,
                    "state": pstate
                })

                # Generate structured finding for EVERY open port detected by Nmap
                host_target = ip_addr or hostname
                risk_meta = RISK_PORT_INFO.get(port_id)
                if risk_meta:
                    findings.append({
                        "host": host_target,
                        "port": port_id,
                        "protocol": proto,
                        "service": svc_name,
                        "title": risk_meta["title"],
                        "severity": risk_meta["severity"],
                        "cvss": risk_meta["cvss"],
                        "cve_ids": "",
                        "cwe_id": risk_meta["cwe_id"],
                        "source_engine": "nmap",
                        "description": risk_meta["description"],
                        "evidence": f"Porta {port_id}/{proto} aperta rilevata da Nmap.\nServizio: {svc_name}\nProdotto/Versione: {full_prod or 'Non identificato'}",
                        "remediation": risk_meta["remediation"],
                        "mitre_tactic": risk_meta["mitre_tactic"],
                        "mitre_technique": risk_meta["mitre_technique"],
                        "ai_insight": f"Audit di sicurezza perimetrale Nmap: {svc_name} esposto su porta {port_id}."
                    })
                else:
                    is_web_or_remote = port_id in [80, 443, 8000, 8080, 8443, 22, 3000, 5000]
                    findings.append({
                        "host": host_target,
                        "port": port_id,
                        "protocol": proto,
                        "service": svc_name,
                        "title": f"Superficie d'Attacco: Servizio {svc_name.upper()} Attivo sulla Porta {port_id}/{proto.upper()}",
                        "severity": "low" if is_web_or_remote else "info",
                        "cvss": 3.7 if is_web_or_remote else 2.5,
                        "cve_ids": "",
                        "cwe_id": "CWE-200",
                        "source_engine": "nmap",
                        "description": f"Il servizio '{svc_name}' è in ascolto e accessibile sulla porta {port_id}/{proto}. È opportuno valutare la necessità operativa di tale esposizione in conformità con le policy di minimizzazione della superficie di attacco.",
                        "evidence": f"Porta {port_id}/{proto} [OPEN]\nServizio: {svc_name}\nBanner/Dettagli: {full_prod or 'N/A'}",
                        "remediation": f"Verificare che l'esposizione della porta {port_id} sia strettamente richiesta. Configurare opportune regole firewall per limitare gli accessi ai soli IP autorizzati.",
                        "mitre_tactic": "Discovery",
                        "mitre_technique": "T1046 - Network Service Discovery",
                        "ai_insight": f"Rilevato servizio attivo ({svc_name}) tramite discovery Nmap."
                    })

                # Port-level scripts
                for sc_el in port_el.findall("script"):
                    sc_id = sc_el.get("id", "")
                    sc_out = sc_el.get("output", "").strip()
                    if sc_out:
                        f = _create_finding_from_script(
                            ip_addr or hostname, port_id, proto, svc_name, sc_id, sc_out
                        )
                        if f:
                            findings.append(f)

        # Host-level scripts
        hostscripts_el = host_el.find("hostscript")
        if hostscripts_el is not None:
            for sc_el in hostscripts_el.findall("script"):
                sc_id = sc_el.get("id", "")
                sc_out = sc_el.get("output", "").strip()
                if sc_out:
                    f = _create_finding_from_script(
                        ip_addr or hostname, 0, "ip", "host", sc_id, sc_out
                    )
                    if f:
                        findings.append(f)

        hosts.append(host_dict)

    return hosts, findings


def _create_finding_from_script(
    host: str, port: int, proto: str, svc: str, script_id: str, output: str
) -> Optional[Dict[str, Any]]:
    # Extract CVEs
    cves = list(set(re.findall(r"CVE-\d{4}-\d{4,7}", output, re.IGNORECASE)))
    cve_str = ", ".join(cves)

    # Determine severity
    lower_out = output.lower()
    severity = "info"
    cvss = 0.0

    if any(k in lower_out for k in ["vulnerable", "state: vulnerable", "critical", "remote code execution"]):
        severity = "critical" if ("rce" in lower_out or "code execution" in lower_out or "ms17-010" in script_id) else "high"
        cvss = 9.8 if severity == "critical" else 7.8
    elif any(k in lower_out for k in ["warning", "medium", "weak", "deprecated", "mitm", "relay"]):
        severity = "medium"
        cvss = 5.5
    elif any(k in lower_out for k in ["low", "leak", "disclosure", "unprotected"]):
        severity = "low"
        cvss = 3.5

    # If script is in curated, inherit metadata
    curated_meta = next((s for s in CURATED_NSE_SCRIPTS if s["id"] == script_id), None)
    if curated_meta and severity == "info" and curated_meta.get("severity") != "info":
        if "vulnerable" in lower_out or "error" in lower_out or len(output) > 20:
            severity = curated_meta["severity"]
            cvss = curated_meta["cvss"]

    # Don't create spam findings for trivial info if output is empty
    if severity == "info" and len(output) < 10:
        return None

    title = f"Nmap NSE [{script_id}] su {host}:{port}"
    if curated_meta:
        title = f"{curated_meta['name']} ({script_id})"

    return {
        "host": host,
        "port": port,
        "protocol": proto,
        "service": svc,
        "title": title,
        "severity": severity,
        "cvss": cvss,
        "cve_ids": cve_str or (curated_meta.get("cve") if curated_meta else ""),
        "cwe_id": "CWE-200" if severity in ["low", "info"] else "CWE-20",
        "source_engine": "nmap",
        "description": f"Lo script NSE '{script_id}' ha restituito un riscontro durante l'audit del servizio {svc} sulla porta {port}.",
        "evidence": output[:2000],
        "remediation": f"Ispezionare la configurazione del servizio {svc} e consultare la documentazione Nmap NSE per lo script {script_id}.",
        "mitre_tactic": curated_meta["mitre_tactic"] if curated_meta else "Discovery",
        "mitre_technique": curated_meta["mitre_technique"] if curated_meta else "T1046 - Network Service Discovery",
        "ai_insight": f"Verificato tramite Nmap NSE {script_id}."
    }
