from cryptor import Encryptor
import cv2
import os
import glob


files = glob.glob(os.path.join('example/', '*'))
for file in files:
    try:
        os.remove(file)
    except Exception as e:
        print(f'Failed to delete {file}. Reason: {e}')

if not os.path.exists('example'):
    os.makedirs('example')

image_path = 'example/image.jpg'

key_path = 'example/encryption_key.bin'
iv_path = 'example/initialization_vector.bin'

def capture_image():
    # Initialize camera
    cap = cv2.VideoCapture(0)  # 0 represents the default camera

    # Capture a frame
    ret, frame = cap.read()

    # Release the camera
    cap.release()

    # Save the captured frame as an image
    cv2.imwrite(image_path, frame)

    return image_path

def main():
    # Capture an image from the camera
    image_path = capture_image()
    print(f"Captured image saved at: {image_path}")

    # Initialize Encryptor with the captured image
    encryptor = Encryptor(path=image_path, outname='example/encrypted_file', create=True)
    encryptor()

    # Save the encryption key and IV
    with open(key_path, 'wb') as key_file:
        key_file.write(encryptor._key)
    with open(iv_path, 'wb') as iv_file:
        iv_file.write(encryptor._iv)

    # Print the encryption key
    print(f"Encryption Key: {encryptor._key.hex()}")

if __name__ == "__main__":
    main()
