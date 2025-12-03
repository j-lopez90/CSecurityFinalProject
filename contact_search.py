import socket
import threading
import time
import os
import atexit

from user_login import session
from contacts import load_contacts
from crypto_utils import load_ca_public_key, verify_certificate_data, extract_email_from_cert, save_certificate_from_data

all_online_users = []
online_contacts = []
_server_lock = threading.Lock()
_lists_lock = threading.Lock()
SERVER_PORT = None
server = None

def cleanup_server():
    global server
    with _server_lock:
        if server:
            try:
                server.close()
            except Exception:
                pass

atexit.register(cleanup_server)

def start_server():
    if not session.email:
        return
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

def run_server():
    global server, SERVER_PORT
    HOST = "0.0.0.0"
    s = None

    for port in range(12345, 12355):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, port))
            s.listen(5)
            SERVER_PORT = port
            print(f"using port: {port}")
            break
        except OSError:
            if s:
                try:
                    s.close()
                except:
                    pass
            s = None
            continue

    if s is None:
        print("Failed to bind any port for server.")
        return

    with _server_lock:
        server = s

    try:
        while True:
            try:
                client, addr = server.accept()
                threading.Thread(target=handle_request, args=(client,), daemon=True).start()
            except OSError:
                break
            except Exception:
                continue
    finally:
        with _server_lock:
            try:
                if server:
                    server.close()
            except:
                pass
            server = None

def handle_request(client_socket):
    try:
        client_socket.settimeout(5)
        data = client_socket.recv(8192)
        if not data:
            client_socket.send(b"ERROR: No data")
            return
        try:
            cert_text = data.decode().strip()
        except Exception:
            client_socket.send(b"ERROR: Invalid encoding")
            return

        if not cert_text.startswith("-----BEGIN CERTIFICATE-----"):
            client_socket.send(b"ERROR: Invalid certificate format")
            return

        ca_public = load_ca_public_key()
        if not verify_certificate_data(cert_text, ca_public):
            client_socket.send(b"ERROR: Certificate verification failed")
            return

        their_email = extract_email_from_cert(cert_text)
        if not their_email:
            client_socket.send(b"ERROR: Could not extract email from certificate")
            return

        save_certificate_from_data(cert_text, their_email)

        with _lists_lock:
            if their_email != session.email and their_email not in all_online_users:
                all_online_users.append(their_email)
                print(f"Users Online: {their_email}")

            user_contacts = load_contacts()
            if their_email != session.email and their_email in user_contacts and their_email not in online_contacts:
                online_contacts.append(their_email)
                # print(f"Online Contact: {their_email}")

        our_cert_path = f"data/certificate/{session.email}.crt"
        if os.path.exists(our_cert_path):
            with open(our_cert_path, "rb") as f:
                client_socket.send(f.read())
        else:
            client_socket.send(b"ERROR: Server certificate not found")
    except Exception:
        try:
            client_socket.send(b"ERROR: Processing failed")
        except:
            pass
    finally:
        try:
            client_socket.close()
        except:
            pass

def start_background_scanner():
    scanner_thread = threading.Thread(target=scanner, daemon=True)
    scanner_thread.start()

def scanner():
    global online_contacts, all_online_users
    while True:
        if session.email:
            discovered = search_for_contacts()
            with _lists_lock:
                all_online_users = discovered
                user_contacts = load_contacts()
                online_contacts.clear()
                for u in all_online_users:
                    if u == session.email:
                        continue
                    if u in user_contacts:
                        online_contacts.append(u)
        time.sleep(10)

def _get_local_ips():
    ips = ["127.0.0.1", "localhost"]
    try:
        hostname = socket.gethostname()
        host_ip = socket.gethostbyname(hostname)
        if host_ip not in ips:
            ips.append(host_ip)
    except Exception:
        pass
    return ips

def search_for_contacts():
    if not session.email:
        return []
    discovered = []
    network_ports = []
    local_ips = _get_local_ips()
    for ip in local_ips:
        for port in range(12345, 12355):
            network_ports.append((ip, port))

    for ip, port in network_ports:
        user_email = check_contact_certificate_exchange(ip, port)
        if user_email and user_email not in discovered and user_email != session.email:
            discovered.append(user_email)
    return discovered

def check_contact_certificate_exchange(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((ip, port))
            our_cert_path = f"data/certificate/{session.email}.crt"
            if not os.path.exists(our_cert_path):
                return None
            with open(our_cert_path, "rb") as f:
                our_cert = f.read()
            sock.send(our_cert)
            resp = sock.recv(8192)
            if not resp:
                return None
            try:
                resp_text = resp.decode().strip()
            except Exception:
                return None
            if resp_text.startswith("-----BEGIN CERTIFICATE-----"):
                ca_public = load_ca_public_key()
                if verify_certificate_data(resp_text, ca_public):
                    their_email = extract_email_from_cert(resp_text)
                    if their_email and their_email != session.email:
                        save_certificate_from_data(resp_text, their_email)
                        # print(f"User found: {their_email}")
                        return their_email
    except (socket.timeout, ConnectionRefusedError):
        pass
    except Exception:
        pass
    return None

def list_online_contacts():
    with _lists_lock:
        if online_contacts:
            for c in online_contacts:
                print(f"* ONLINE: {c}")
        else:
            print("No contacts currently online")

def list_all_users():
    with _lists_lock:
        if all_online_users:
            # print("All users Online: ")
            for u in all_online_users:
                user_contacts = load_contacts()
                if u in user_contacts:
                    print(f"{u} contact")
                else:
                    print(f"{u}")
        else:
            print("NO users currently online")
