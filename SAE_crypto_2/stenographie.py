from PIL import Image


def meme_image(nom_image1: str, nom_image2: str) -> bool:
    """
    Fonction qui compare deux images pixel par pixel et qui renvoie True si elles sont identiques

    Args:
        nom_image1 (str): Le nom de la première image
        nom_image2 (str): Le nom de la deuxième image

    Returns:
        bool: True si les images sont identiques, False sinon
    """
    image = Image.open(nom_image1)
    image2 = Image.open(nom_image2)
    nombre_colonne = image.size[0]
    nombre_ligne = image.size[1]
    for ind in range(nombre_ligne):
        for ind2 in range(nombre_colonne):
            pixel_en_cours_img_1 = image.getpixel((ind2, ind))
            pixel_en_cours_img_2 = image2.getpixel((ind2, ind))
            if pixel_en_cours_img_1 != pixel_en_cours_img_2:
                return False
    return True


def retrouve_cle() -> str:
    """
    Fonction qui retrouve la clé de cryptage AES cachée dans l'image

    Returns:
        str: La clé de cryptage AES
    """
    image2 = Image.open("sujet/rossignol2.bmp")
    nombre_colonne, nombre_ligne = image2.size[0], image2.size[1]
    cle = ""
    cpt = 0
    for ind in range(nombre_ligne):
        for ind2 in range(nombre_colonne):
            if cpt < 64:
                pixel_en_cours_img_2 = image2.getpixel((ind2, ind))
                cle += bin(pixel_en_cours_img_2)[-1]
                cpt += 1
    return cle
