def log_packet(data):
    with open("traffic.log", "a") as f:
        f.write(data + "\n")