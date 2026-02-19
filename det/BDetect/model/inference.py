# import os
# import torch
# import torch.nn as nn
# from torchvision import transforms
# from PIL import Image
# import pandas as pd
# from model.train_model import BotnetCNN


# def load_model(model_path="model/model.pth"):
#     model = BotnetCNN()
#     model.load_state_dict(torch.load(model_path))
#     model.eval()
#     return model

# def predict_image(model, image_path):
#     transform = transforms.Compose([
#         transforms.Grayscale(),
#         transforms.Resize((32, 32)),
#         transforms.ToTensor()
#     ])
#     image = Image.open(image_path).convert("L")
#     input_tensor = transform(image).unsqueeze(0)
#     with torch.no_grad():
#         output = model(input_tensor)
#         probs = torch.softmax(output, dim=1)
#         confidence = probs[0][1].item() * 100  # Confidence of being botnet
#     return confidence

# def run_inference_on_folder(image_dir="data/images", output_csv="data/results.csv"):
#     model = load_model()
#     results = []

#     for filename in os.listdir(image_dir):
#         if filename.endswith(".png"):
#             image_path = os.path.join(image_dir, filename)
#             confidence = predict_image(model, image_path)
#             results.append({
#                 "device": filename.replace(".png", ""),
#                 "confidence": round(confidence, 2)
#             })

#     df = pd.DataFrame(results)
#     df.to_csv(output_csv, index=False)
#     print(f"[✓] Inference complete. Results saved to {output_csv}")
#     return df

# if __name__ == "__main__":
#     run_inference_on_folder()



# ============================08-10-25===========================


import os
import torch
import torch.nn as nn
from torchvision import transforms
from PIL import Image
import pandas as pd
from model.train_model import BotnetCNN

PREDICTION_LOG = "data/prediction_log.csv"

def load_model(model_path="model/model.pth"):
    model = BotnetCNN()
    model.load_state_dict(torch.load(model_path))
    model.eval()
    return model

def get_confidence_history(ip):
    try:
        df = pd.read_csv(PREDICTION_LOG, names=["timestamp", "enriched_ip", "confidence", "status"], encoding="utf-8", on_bad_lines="skip")
        df["ip"] = df["enriched_ip"].str.extract(r"(\d+\.\d+\.\d+\.\d+)")
        history = df[df["ip"] == ip]
        if "botnet" in history["status"].values:
            return []  # Never boost botnet
        return history["confidence"].dropna().tolist()
    except:
        return []

def adjust_confidence(ip, raw_score):
    history = get_confidence_history(ip)
    if not history:
        return raw_score
    boost = min(2.0, sum(history[-3:]) / 100)  # Small boost based on recent scores
    return min(100.0, raw_score + boost)

def predict_image(model, image_path):
    transform = transforms.Compose([
        transforms.Grayscale(),
        transforms.Resize((32, 32)),
        transforms.ToTensor()
    ])
    image = Image.open(image_path).convert("L")
    input_tensor = transform(image).unsqueeze(0)
    with torch.no_grad():
        output = model(input_tensor)
        probs = torch.softmax(output, dim=1)
        raw_confidence = probs[0][1].item() * 100  # Confidence of being botnet
    return raw_confidence

def run_inference_on_folder(image_dir="data/images", output_csv="data/results.csv"):
    model = load_model()
    results = []

    for filename in os.listdir(image_dir):
        if filename.endswith(".png"):
            image_path = os.path.join(image_dir, filename)
            raw_confidence = predict_image(model, image_path)
            ip = filename.replace(".png", "")
            final_confidence = adjust_confidence(ip, raw_confidence)
            results.append({
                "device": ip,
                "confidence": round(final_confidence, 2)
            })

    df = pd.DataFrame(results)
    df.to_csv(output_csv, index=False)
    print(f"[✓] Inference complete. Results saved to {output_csv}")
    return df

if __name__ == "__main__":
    run_inference_on_folder()
