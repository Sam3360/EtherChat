import base64
import hashlib
import json
import os
import queue
import secrets
import socket
import struct
import threading
import time
import uuid
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import qrcode
from PIL import ImageTk

APP = "EtherChat"
DISCOVERY_PORT = 39393
CHAT_PORT = 39394
MAGIC = b"ETCH"
MAX_FRAME = 12 * 1024 * 1024
DATA_DIR = Path(os.getenv("APPDATA", Path.home())) / "EtherChat"
DATA_DIR.mkdir(parents=True, exist_ok=True)
IDENTITY_FILE = DATA_DIR / "identity.json"
SETTINGS_FILE = DATA_DIR / "settings.json"


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode())


def send_frame(sock, obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    if len(raw) > MAX_FRAME:
        raise ValueError("Frame too large")
    sock.sendall(MAGIC + struct.pack("!I", len(raw)) + raw)


def recv_exact(sock, n):
    out = bytearray()
    while len(out) < n:
        part = sock.recv(n - len(out))
        if not part:
            raise ConnectionError("Connection closed")
        out.extend(part)
    return bytes(out)


def recv_frame(sock):
    if recv_exact(sock, 4) != MAGIC:
        raise ConnectionError("Invalid EtherChat frame")
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size > MAX_FRAME:
        raise ConnectionError("Frame too large")
    return json.loads(recv_exact(sock, size).decode())


def derive_session_key(shared: bytes, a: bytes, b: bytes) -> bytes:
    salt = hashlib.sha256(a + b).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"EtherChat LAN v1").derive(shared)


def encrypt(key: bytes, obj: dict) -> str:
    nonce = secrets.token_bytes(12)
    raw = json.dumps(obj, separators=(",", ":")).encode()
    ct = AESGCM(key).encrypt(nonce, raw, b"EtherChat")
    return b64e(nonce + ct)


def decrypt(key: bytes, token: str) -> dict:
    raw = b64d(token)
    return json.loads(AESGCM(key).decrypt(raw[:12], raw[12:], b"EtherChat").decode())


class Peer:
    def __init__(self, app, sock, addr, outbound=False):
        self.app = app
        self.sock = sock
        self.addr = addr
        self.outbound = outbound
        self.send_lock = threading.Lock()
        self.alive = True
        self.peer_id = None
        self.username = "Unknown"
        self.public_key = None
        self.session_key = None
        self.rooms = set()

    def send(self, payload):
        if not self.alive or not self.session_key:
            return
        with self.send_lock:
            send_frame(self.sock, {"type": "data", "payload": encrypt(self.session_key, payload)})

    def close(self):
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


class EtherChat(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EtherChat")
        self.geometry("980x680")
        self.minsize(820, 560)

        self.peer_id = uuid.uuid4().hex
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.username = self.load_username()
        self.peers = {}
        self.peers_lock = threading.Lock()
        self.rooms = {"General"}
        self.current_room = "General"
        self.events = queue.Queue()
        self.trusted = self.load_trusted()
        self.discovery_socket = None
        self.server_socket = None
        self.running = True
        self.port = CHAT_PORT
        self.local_ip = self.get_local_ip()

        self.protocol("WM_DELETE_WINDOW", self.shutdown)
        self.build_ui()
        self.start_network()
        self.after(100, self.process_events)

    def load_username(self):
        try:
            data = json.loads(SETTINGS_FILE.read_text())
            name = data.get("username")
            if name:
                return name
        except Exception:
            pass
        return socket.gethostname()[:24] or "EtherUser"

    def save_username(self):
        SETTINGS_FILE.write_text(json.dumps({"username": self.username}, indent=2))

    def load_trusted(self):
        try:
            return json.loads((DATA_DIR / "trusted.json").read_text())
        except Exception:
            return {}

    def save_trusted(self):
        (DATA_DIR / "trusted.json").write_text(json.dumps(self.trusted, indent=2))

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return "127.0.0.1"

    def build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="EtherChat", font=("Segoe UI", 20, "bold")).pack(side="left")
        ttk.Label(top, text=f"  •  {self.local_ip}:{self.port}", foreground="#666").pack(side="left")
        ttk.Button(top, text="Change username", command=self.change_username).pack(side="right")
        ttk.Button(top, text="QR Pairing", command=self.show_qr).pack(side="right", padx=6)

        main = ttk.Panedwindow(self, orient="horizontal")
        main.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        left = ttk.Frame(main, padding=8)
        center = ttk.Frame(main, padding=8)
        main.add(left, weight=1)
        main.add(center, weight=4)

        ttk.Label(left, text="LOCAL NETWORK", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.peer_list = tk.Listbox(left, height=14, activestyle="none")
        self.peer_list.pack(fill="both", expand=True, pady=8)
        self.peer_list.bind("<Double-Button-1>", self.start_direct_chat)

        ttk.Label(left, text="ROOMS", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(10, 0))
        roombar = ttk.Frame(left)
        roombar.pack(fill="x", pady=8)
        self.room_list = tk.Listbox(roombar, height=7, activestyle="none")
        self.room_list.pack(fill="both", expand=True)
        self.room_list.insert("end", "General")
        self.room_list.selection_set(0)
        self.room_list.bind("<<ListboxSelect>>", self.select_room)
        ttk.Button(roombar, text="+ Room", command=self.add_room).pack(fill="x", pady=(6, 0))

        self.status = ttk.Label(left, text="Searching for EtherChat devices…", foreground="#666")
        self.status.pack(anchor="w", pady=(8, 0))

        self.chat_title = ttk.Label(center, text="General", font=("Segoe UI", 16, "bold"))
        self.chat_title.pack(anchor="w")

        self.chat = tk.Text(center, state="disabled", wrap="word", font=("Segoe UI", 10))
        self.chat.pack(fill="both", expand=True, pady=8)

        self.typing = ttk.Label(center, text="", foreground="#777")
        self.typing.pack(anchor="w")

        sendbar = ttk.Frame(center)
        sendbar.pack(fill="x")
        self.entry = ttk.Entry(sendbar)
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<Return>", self.send_message)
        self.entry.bind("<KeyPress>", self.local_typing)
        ttk.Button(sendbar, text="Send", command=self.send_message).pack(side="left", padx=6)
        ttk.Button(sendbar, text="File", command=self.send_file).pack(side="left")

    def append_chat(self, text):
        self.chat.configure(state="normal")
        self.chat.insert("end", text + "\n")
        self.chat.see("end")
        self.chat.configure(state="disabled")

    def change_username(self):
        name = simpledialog.askstring("Username", "Choose a username:", initialvalue=self.username, parent=self)
        if name and name.strip():
            self.username = name.strip()[:32]
            self.save_username()
            self.broadcast_hello()

    def add_room(self):
        name = simpledialog.askstring("New room", "Room name:", parent=self)
        if name and name.strip():
            name = name.strip()[:40]
            self.rooms.add(name)
            self.room_list.insert("end", name)
            self.room_list.selection_clear(0, "end")
            self.room_list.selection_set("end")
            self.current_room = name
            self.chat_title.config(text=name)
            self.broadcast({"kind": "room", "room": name})

    def select_room(self, _=None):
        sel = self.room_list.curselection()
        if sel:
            self.current_room = self.room_list.get(sel[0])
            self.chat_title.config(text=self.current_room)
            self.append_chat(f"— switched to #{self.current_room} —")

    def start_direct_chat(self, _=None):
        sel = self.peer_list.curselection()
        if not sel:
            return
        line = self.peer_list.get(sel[0])
        pid = line.split(" | ")[0]
        peer = self.peers.get(pid)
        if peer:
            self.append_chat(f"— direct connection with {peer.username} ({peer.addr[0]}) —")

    def local_typing(self, _=None):
        self.broadcast({"kind": "typing", "room": self.current_room, "username": self.username, "typing": True})
        self.after(900, lambda: self.broadcast({"kind": "typing", "room": self.current_room, "username": self.username, "typing": False}))

    def send_message(self, _=None):
        text = self.entry.get().strip()
        if not text:
            return "break"
        self.entry.delete(0, "end")
        msg = {
            "kind": "message",
            "room": self.current_room,
            "username": self.username,
            "message": text,
            "time": time.strftime("%H:%M"),
            "id": uuid.uuid4().hex,
        }
        self.append_chat(f"[{msg['time']}] {self.username}: {text}")
        self.broadcast(msg)
        return "break"

    def send_file(self):
        path = filedialog.askopenfilename(parent=self)
        if not path:
            return
        try:
            data = Path(path).read_bytes()
            if len(data) > 8 * 1024 * 1024:
                messagebox.showerror("File too large", "EtherChat currently limits one transfer to 8 MB.")
                return
            msg = {
                "kind": "file",
                "room": self.current_room,
                "username": self.username,
                "filename": Path(path).name,
                "data": b64e(data),
                "time": time.strftime("%H:%M"),
            }
            self.append_chat(f"[{msg['time']}] {self.username} sent {msg['filename']} ({len(data)/1024:.1f} KB)")
            self.broadcast(msg)
        except Exception as e:
            messagebox.showerror("File error", str(e))

    def broadcast(self, payload):
        with self.peers_lock:
            peers = list(self.peers.values())
        for peer in peers:
            try:
                peer.send(payload)
            except Exception:
                peer.close()

    def broadcast_hello(self):
        self.broadcast({"kind": "hello", "username": self.username})

    def start_network(self):
        threading.Thread(target=self.tcp_server, daemon=True).start()
        threading.Thread(target=self.discovery_listener, daemon=True).start()
        threading.Thread(target=self.discovery_sender, daemon=True).start()

    def tcp_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind(("", CHAT_PORT))
        except OSError:
            self.server_socket.bind(("", 0))
            self.port = self.server_socket.getsockname()[1]
        self.server_socket.listen(20)
        self.events.put(("status", f"Listening on {self.local_ip}:{self.port}"))
        while self.running:
            try:
                sock, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_connection, args=(sock, addr, False), daemon=True).start()
            except Exception:
                break

    def discovery_listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("", DISCOVERY_PORT))
        except OSError:
            return
        self.discovery_socket = s
        while self.running:
            try:
                data, addr = s.recvfrom(4096)
                obj = json.loads(data.decode())
                if obj.get("app") != APP or obj.get("id") == self.peer_id:
                    continue
                if obj.get("port") == self.port and obj.get("id"):
                    self.connect_to_peer(addr[0], int(obj["port"]), obj["id"])
            except Exception:
                if self.running:
                    continue

    def discovery_sender(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        while self.running:
            packet = {
                "app": APP,
                "version": 1,
                "id": self.peer_id,
                "username": self.username,
                "port": self.port,
                "public_key": b64e(self.public_key),
            }
            try:
                s.sendto(json.dumps(packet).encode(), ("255.255.255.255", DISCOVERY_PORT))
            except Exception:
                pass
            time.sleep(2)

    def connect_to_peer(self, ip, port, pid):
        if pid == self.peer_id:
            return
        with self.peers_lock:
            existing = self.peers.get(pid)
            if existing and existing.alive:
                return
        try:
            sock = socket.create_connection((ip, port), timeout=2)
            peer = Peer(self, sock, (ip, port), outbound=True)
            with self.peers_lock:
                self.peers[pid] = peer
            threading.Thread(target=self.handle_connection, args=(sock, (ip, port), True, peer), daemon=True).start()
        except Exception:
            pass

    def handle_connection(self, sock, addr, outbound=False, peer=None):
        if peer is None:
            peer = Peer(self, sock, addr, outbound)
        try:
            my_priv = X25519PrivateKey.generate()
            my_pub = my_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            hello = {
                "type": "handshake",
                "id": self.peer_id,
                "username": self.username,
                "public_key": b64e(self.public_key),
                "ephemeral": b64e(my_pub),
                "port": self.port,
            }
            send_frame(sock, hello)
            remote = recv_frame(sock)
            if remote.get("type") != "handshake":
                raise ConnectionError("Bad handshake")
            peer.peer_id = remote["id"]
            peer.username = remote.get("username", "Unknown")
            peer.public_key = b64d(remote["public_key"])
            remote_ephemeral = b64d(remote["ephemeral"])

            shared = my_priv.exchange(X25519PublicKey.from_public_bytes(remote_ephemeral))
            peer.session_key = derive_session_key(shared, my_pub, remote_ephemeral)

            # Tie simultaneous connections together so both peers keep only one.
            with self.peers_lock:
                old = self.peers.get(peer.peer_id)
                if old and old is not peer:
                    keep_new = self.peer_id < peer.peer_id
                    if keep_new:
                        old.close()
                        self.peers[peer.peer_id] = peer
                    else:
                        peer.close()
                        return
                else:
                    self.peers[peer.peer_id] = peer

            peer.send({"kind": "hello", "username": self.username})
            self.events.put(("peer", None))
            self.events.put(("status", f"{len(self.peers)} device(s) connected"))

            while self.running and peer.alive:
                frame = recv_frame(sock)
                if frame.get("type") != "data":
                    continue
                payload = decrypt(peer.session_key, frame["payload"])
                self.handle_payload(peer, payload)
        except Exception:
            peer.close()
        finally:
            with self.peers_lock:
                if peer.peer_id in self.peers and self.peers[peer.peer_id] is peer:
                    del self.peers[peer.peer_id]
            self.events.put(("peer", None))

    def handle_payload(self, peer, p):
        kind = p.get("kind")
        if kind == "hello":
            peer.username = p.get("username", peer.username)
            self.events.put(("peer", None))
        elif kind == "typing":
            if p.get("room") == self.current_room and p.get("typing"):
                self.events.put(("typing", f"{peer.username} is typing…"))
            else:
                self.events.put(("typing", ""))
        elif kind == "room":
            room = p.get("room")
            if room and room not in self.rooms:
                self.rooms.add(room)
                self.events.put(("room", room))
        elif kind == "message":
            if p.get("room") == self.current_room:
                self.events.put(("chat", f"[{p.get('time','')}] {peer.username}: {p.get('message','')}"))
        elif kind == "file":
            if p.get("room") == self.current_room:
                try:
                    data = b64d(p["data"])
                    safe = Path(p["filename"]).name
                    target = filedialog.asksaveasfilename(
                        parent=self, initialfile=safe, title=f"Save file from {peer.username}"
                    )
                    if target:
                        Path(target).write_bytes(data)
                        self.events.put(("chat", f"Received {safe} from {peer.username}"))
                except Exception as e:
                    self.events.put(("chat", f"File receive failed: {e}"))

    def process_events(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "chat":
                    self.append_chat(value)
                elif kind == "typing":
                    self.typing.config(text=value)
                elif kind == "status":
                    self.status.config(text=value)
                elif kind == "peer":
                    self.refresh_peers()
                elif kind == "room":
                    if value not in [self.room_list.get(i) for i in range(self.room_list.size())]:
                        self.room_list.insert("end", value)
        except queue.Empty:
            pass
        if self.running:
            self.after(100, self.process_events)

    def refresh_peers(self):
        self.peer_list.delete(0, "end")
        with self.peers_lock:
            peers = list(self.peers.values())
        for p in sorted(peers, key=lambda x: x.username.lower()):
            if p.alive:
                self.peer_list.insert("end", f"{p.peer_id} | {p.username} | {p.addr[0]}")

    def show_qr(self):
        payload = {
            "app": APP,
            "v": 1,
            "id": self.peer_id,
            "username": self.username,
            "ip": self.local_ip,
            "port": self.port,
            "pub": b64e(self.public_key),
        }
        raw = json.dumps(payload, separators=(",", ":"))
        qr = qrcode.make(raw)
        qr = qr.resize((360, 360))
        win = tk.Toplevel(self)
        win.title("EtherChat QR Pairing")
        ttk.Label(win, text=f"Pair with {self.username}", font=("Segoe UI", 13, "bold")).pack(pady=8)
        img = ImageTk.PhotoImage(qr)
        label = ttk.Label(win, image=img)
        label.image = img
        label.pack(padx=12, pady=8)
        ttk.Label(win, text="Scan this QR with your EtherChat companion device\nor use the pairing data with a compatible client.").pack(pady=(0, 10))
        ttk.Button(win, text="Copy pairing data", command=lambda: self.copy_to_clipboard(raw)).pack(pady=(0, 12))

    def copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()

    def shutdown(self):
        self.running = False
        for p in list(self.peers.values()):
            p.close()
        try:
            self.server_socket.close()
        except Exception:
            pass
        try:
            self.discovery_socket.close()
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    # X25519 is imported lazily above for compatibility with older environments.
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    app = EtherChat()
    app.mainloop()
