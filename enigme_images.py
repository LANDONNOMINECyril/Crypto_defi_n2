from PIL import Image

def compare_image(path_image):
    image = Image.open(path_image)
    res = ""
    largeur, hauteur = image.size
    for y in range(hauteur):
        for x in range(largeur):
            pixel = image.getpixel((x, y))
            res += str(pixel % 2)
            if len(res) == 64:
                return res
    return None

print(compare_image("rossignol1.bmp"))