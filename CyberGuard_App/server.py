import time
import psutil
import platform
import datetime
from fastapi import FastAPI
from threading import Thread
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import deque

app = FastAPI()
packet_buffer = deque(maxlen=100)
last_net = psutil.net_io_counters()
last_time = time.time()

def packet_callback(pkt):
    if IP in pkt:
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "ICMP" if ICMP in pkt else "Other"
        packet_data = {
            "src": pkt[IP].src, "dst": pkt[IP].dst, "proto": proto,
            "size": f"{len(pkt)} B", "time": time.strftime('%H:%M:%S')
        }
        packet_buffer.append(packet_data)

def start_sniffing():
    print("[*] Sniffer started...")
    sniff(prn=packet_callback, store=0)

Thread(target=start_sniffing, daemon=True).start()

@app.get("/stats")
def get_stats():
    global last_net, last_time
    now = time.time()
    curr_net = psutil.net_io_counters()
    dt = max(now - last_time, 0.01)
    speed_down = (curr_net.bytes_recv - last_net.bytes_recv) / dt
    speed_up = (curr_net.bytes_sent - last_net.bytes_sent) / dt
    last_net, last_time = curr_net, now
    disk = psutil.disk_usage('/')
    uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())
    return {
        "cpu": psutil.cpu_percent(),
        "ram": psutil.virtual_memory().percent,
        "disk": {"percent": disk.percent, "used": disk.used // 1024**3, "total": disk.total // 1024**3},
        "net_total": {"rx": curr_net.bytes_recv // 1024**2, "tx": curr_net.bytes_sent // 1024**2},
        "speed": {"down": speed_down, "up": speed_up},
        "sys_info": {
            "node": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "proc_count": len(psutil.pids()),
            "uptime": str(uptime).split('.')[0]
        }
    }

@app.get("/packets")
def get_packets():
    data = list(packet_buffer)
    packet_buffer.clear()
    return data

@app.get("/connections")
def get_connections():
    return [{"local": f"{c.laddr.ip}:{c.laddr.port}",
             "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "LISTEN",
             "status": c.status, "pid": c.pid}
            for c in psutil.net_connections(kind='inet')][:100]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
