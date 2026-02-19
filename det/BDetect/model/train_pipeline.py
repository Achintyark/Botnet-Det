# import os
# from model.train_model import train_model
# from preprocess.convert_pcap_to_png import convert_pcap_to_png

# # def batch_train_from_pcaps(pcap_folder="data/pcap/", label="benign"):
# #     image_folder = "data/images/"
# #     os.makedirs(image_folder, exist_ok=True)
# #     for file in os.listdir(pcap_folder):
# #         if file.endswith(".pcap"):
# #             image_path = convert_pcap_to_png(os.path.join(pcap_folder, file))
# #             if image_path:
# #                 label_path = image_path.replace(".png", f"_{label}.png")
# #                 os.rename(image_path, label_path)
# #     train_model(image_folder)
# def batch_train_from_pcaps(pcap_folder="data/pcap/", label="benign"):
#     image_folder = "data/images/"
#     os.makedirs(image_folder, exist_ok=True)
#     for file in os.listdir(pcap_folder):
#         if file.endswith(".pcap"):
#             image_path = convert_pcap_to_png(os.path.join(pcap_folder, file))
#             if image_path:
#                 label_path = image_path.replace(".png", f"_{label}.png")
#                 os.rename(image_path, label_path)
#     train_model(image_folder)



# ============================08-10-25===========================
import os
from model.train_model import train_model
from preprocess.convert_pcap_to_png import convert_pcap_to_png

def batch_train_from_pcaps(pcap_folder="data/pcap/", label="benign"):
    image_folder = "data/images/"
    os.makedirs(image_folder, exist_ok=True)

    processed = 0
    for file in os.listdir(pcap_folder):
        if file.endswith(".pcap"):
            pcap_path = os.path.join(pcap_folder, file)
            print(f"[🔄] Converting {file} to image...")
            image_path = convert_pcap_to_png(pcap_path)

            if image_path and os.path.exists(image_path):
                label_path = image_path.replace(".png", f"_{label}.png")
                if not os.path.exists(label_path):
                    os.rename(image_path, label_path)
                    print(f"[✅] Labeled image saved as {label_path}")
                    processed += 1
                else:
                    print(f"[⚠️] Skipped: {label_path} already exists.")
            else:
                print(f"[❌] Failed to convert {file} to image.")

    if processed > 0:
        print(f"[📚] Training model with {processed} labeled samples...")
        train_model(image_folder)
        print(f"[✓] Training complete.")
    else:
        print(f"[⚠️] No new samples to train.")
