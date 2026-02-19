import os
import numpy as np
import cv2
import pyshark

def pcap_to_bytes(pcap_file, max_bytes=1024):
    cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)
    byte_stream = bytearray()

    try:
        for pkt in cap:
            raw = pkt.get_raw_packet()
            if raw:
                byte_stream.extend(raw)
            if len(byte_stream) >= max_bytes:
                break
    except Exception as e:
        print(f"[!] Error reading {pcap_file}: {e}")
    finally:
        cap.close()

    byte_stream = byte_stream[:max_bytes]
    return np.frombuffer(byte_stream, dtype=np.uint8)

def bytes_to_image(byte_array, image_size=(32, 32)):
    padded = np.zeros(image_size[0] * image_size[1], dtype=np.uint8)
    length = min(len(byte_array), padded.size)
    padded[:length] = byte_array[:length]
    img = padded.reshape(image_size)
    return img

def classify_pcap(pcap_filename):
    fname = pcap_filename.lower()
    if "botnet" in fname or "malware" in fname or "infected" in fname:
        return "botnet"
    else:
        return "benign"

def convert_pcap_to_png(pcap_path, base_output_dir="data/images"):
    label = classify_pcap(os.path.basename(pcap_path))
    output_dir = os.path.join(base_output_dir, label)
    os.makedirs(output_dir, exist_ok=True)

    byte_array = pcap_to_bytes(pcap_path)
    image = bytes_to_image(byte_array)
    filename = os.path.basename(pcap_path).replace(".pcap", ".png")
    output_path = os.path.join(output_dir, filename)
    cv2.imwrite(output_path, image)
    print(f"[✓] Saved image: {output_path}")
    return output_path

def batch_convert_pcap_folder(pcap_dir="data/pcap", base_output_dir="data/images"):
    if not os.path.exists(pcap_dir):
        print(f"[!] PCAP folder not found: {pcap_dir}")
        return

    pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith(".pcap")]
    if not pcap_files:
        print("[!] No .pcap files found to convert.")
        return

    print(f"[🔄] Converting {len(pcap_files)} .pcap files...")
    for pcap_file in pcap_files:
        full_path = os.path.join(pcap_dir, pcap_file)
        convert_pcap_to_png(full_path, base_output_dir)

if __name__ == "__main__":
    batch_convert_pcap_folder()
