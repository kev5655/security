import os
import subprocess
import sys
import threading
import time


def stream_output(node_name, stream, label):
    for line in iter(stream.readline, ''):
        line = line.rstrip()
        if line:
            print(f"[{node_name} {label}] {line}")
    stream.close()

def main():
    num_nodes = 3
    if len(sys.argv) > 1:
        try:
            num_nodes = int(sys.argv[1])
        except ValueError:
            print("❌ Usage: python start.py [num_nodes]")
            sys.exit(1)

    app_name = "./chord_node"

    print("🔨 Compiling Go code...")
    compile_process = subprocess.run(['go', 'build', '-o', 'chord_node', 'node.go'])
    
    if compile_process.returncode != 0:
        print("❌ Compilation failed. Please check your Go code.")
        sys.exit(1)

    print(f"🚀 Starting {num_nodes} nodes in this shell...")

    processes = {}
    threads = []
    for i in range(1, num_nodes + 1):
        node_name = f"node{i}"
        cmd = [app_name, node_name]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        processes[node_name] = proc
        t_out = threading.Thread(
            target=stream_output,
            args=(node_name, proc.stdout, "OUT"),
            daemon=True,
        )
        t_err = threading.Thread(
            target=stream_output,
            args=(node_name, proc.stderr, "ERR"),
            daemon=True,
        )
        t_out.start()
        t_err.start()
        threads.extend([t_out, t_err])
        time.sleep(0.05)

    print("✅ Nodes started.")
    print("Commands:")
    print("  send <nodeName> <message>   (example: send node1 node2 hello)")
    print("  broadcast <message>")
    print("  stop | exit | quit | Ctrl+D")

    # Read commands from this terminal and forward to node stdin
    try:
        while True:
            user_input = sys.stdin.readline()
            if user_input == "":
                # EOF (Ctrl+D)
                break

            text = user_input.strip()
            if text.lower() in ['stop', 'exit', 'quit']:
                break

            if text.startswith("send "):
                parts = text.split(" ", 2)
                if len(parts) < 3:
                    print("Format: send <nodeName> <message>")
                    continue
                node_name = parts[1]
                msg = parts[2]
                proc = processes.get(node_name)
                if not proc or proc.poll() is not None:
                    print(f"❌ {node_name} is not running")
                    continue
                try:
                    # Forward raw line to the node process
                    proc.stdin.write(msg + "\n")
                    proc.stdin.flush()
                except Exception:
                    print(f"❌ Failed to send to {node_name}")
                continue

            if text.startswith("broadcast "):
                msg = text[len("broadcast "):]
                if not msg:
                    print("Format: broadcast <message>")
                    continue
                for node_name, proc in processes.items():
                    if proc.poll() is not None:
                        continue
                    try:
                        proc.stdin.write(msg + "\n")
                        proc.stdin.flush()
                    except Exception:
                        print(f"❌ Failed to send to {node_name}")
                continue

            print("Unknown command. Try: send, broadcast, stop")
    except KeyboardInterrupt:
        pass

    print("\nShutting down nodes...")

    # Terminate launched nodes
    for proc in processes.values():
        try:
            proc.terminate()
        except Exception:
            pass

    # Give processes a moment to close
    time.sleep(0.2)

    # Ensure anything still running is stopped
    for proc in processes.values():
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass

    # Clean up the compiled binary
    if os.path.exists("chord_node"):
        os.remove("chord_node")

    print("Done! All nodes and windows have been closed.")

if __name__ == "__main__":
    main()
    