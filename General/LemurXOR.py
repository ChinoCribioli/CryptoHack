# Challenge from the XOR section in https://cryptohack.org/challenges/general/

import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from PIL import Image
import numpy as np
import io
flag_path = "images/flag.png"
lemur_path = "images/lemur.png"
im = Image.open(flag_path)
flag = list(im.getdata())
im = Image.open(lemur_path)
lemur = list(im.getdata())

def pixel_xor(p1,p2):
	return (p1[0]^p2[0], p1[1]^p2[1], p1[2]^p2[2])

newImage = []
for i in range(327):
	newImage.append([])
	for j in range(582):
		newImage[i].append(pixel_xor(flag[582*i+j], lemur[582*i+j]))


imageArray = np.array(newImage, dtype=np.uint8)
print(imageArray.shape)
im = Image.fromarray(imageArray)

im.show()
