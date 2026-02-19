from PIL import Image
import matplotlib.pyplot as plt
import torchvision.transforms as transforms

def show_prediction_image(image_path):
    image = Image.open(image_path)
    transform = transforms.Compose([
        transforms.Resize((128, 128)),
        transforms.ToTensor()
    ])
    tensor = transform(image)
    plt.imshow(tensor.permute(1, 2, 0), cmap="gray")
    plt.title("Prediction Input Image")
    plt.axis("off")
    plt.show()
