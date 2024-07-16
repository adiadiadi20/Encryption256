import Crypto
import numpy as np
from Crypto.Cipher import AES
from Crypto import Random
from pathlib import Path
from PIL import Image
from typing import Any, TypeVar, Union, Tuple

Rd = TypeVar('Rd')

def read_key(key_path):
    with open(key_path, 'rb') as key_file:
        return key_file.read()

class Cryptor(object):
    def __init__(self, path, outname, create, **kwargs):
        self.path = path
        self.outname = outname
        if create:
            self._key, self._iv = self.initialize_keys()
        else:
            self._key = read_key(kwargs.get('_key'))
            self._iv = read_key(kwargs.get('_iv'))
        self.cipher = self.create_cipher()

    def read_image(self):
        """Read the image based on path argument"""
        in_data = np.asarray(Image.open(self.path))
        _shape = np.asarray(in_data.shape, dtype=np.int32)
        print(f"Image shape: {_shape}")
        return in_data.tobytes(order='C'), _shape.tobytes(order='C')

    def read_data(self):
        """Read data (crypted or encrypted)"""
        with open(self.path, 'rb') as infile:
            data = infile.read()
        return data

    def write_data(self, outpath: str, data: Any):
        with open(outpath, 'wb') as encfile:
            encfile.write(data)

    def initialize_keys(self) -> Union[Rd, Rd]:
        """Initialize key and initialize vector"""
        _key = Random.new().read(32)  # 256-bit key
        _iv = Random.new().read(AES.block_size)
        return _key, _iv

    def create_cipher(self, algo: str = 'AES'):
        """Create new cipher with predefined algorithm name."""
        tmp_ciph = getattr(Crypto.Cipher, algo)
        _cipher = tmp_ciph.new(self._key, AES.MODE_CFB, self._iv)
        return _cipher

class Encryptor(Cryptor):
    def __init__(self, path, outname, create, **kwargs):
        super().__init__(path, outname, create, **kwargs)
        self.data, self.shape = self.read_image()
        self.enc_data = self._encrypt(data=self.data)
        self.enc_shape = self._encrypt(data=self.shape)

    def __call__(self):
        self.save_cryptedata(input_file=self.enc_data, filename=self.outname) 
        self.save_cryptedata(input_file=self.enc_shape, filename=self.outname + '_shape')

    def save_cryptedata(self, input_file: Any, filename: str):
        with open(filename, 'wb') as encfile:
            encfile.write(input_file)

    def _encrypt(self, data: Union[np.ndarray, Tuple]):
        return self.cipher.encrypt(data) 


class Decryptor(Cryptor):
    def __init__(self, path: Union[str, Path], outname: str, create: bool, **kwargs):
        super().__init__(path=path, outname=outname, create=create, **kwargs)

    def __call__(self):
        self.data = self.load_cryptedata(filename=self.path)
        self.shape = self.load_cryptedata(filename=self.path + '_shape')
        self.dec_data = self._decrypt(self.data)
        self.dec_shape = np.frombuffer(self._decrypt(self.shape), dtype=np.int32)
        self.dec_numpy = self._get_numpy()
        decrypted_image = Image.fromarray(self.dec_numpy)
        decrypted_image.save(f"{self.outname}.jpg", format='JPEG')
        self.dec_numpy1 = self._get_numpy_enc()
        decrypted_image1 = Image.fromarray(self.dec_numpy1)
        decrypted_image1.save(f"example/crypted_image.jpg", format='JPEG')

    def load_cryptedata(self, filename: Union[str, Path]) -> bytes:
        with open(filename, 'rb') as infile:
            data = infile.read()
        return data

    def _decrypt(self, file: Any) -> bytes:
        return self.cipher.decrypt(file)
    
    def _get_numpy_enc(self) -> np.ndarray:
        return np.frombuffer(self.data, dtype=np.uint8).reshape(tuple(self.dec_shape))
    def _get_numpy(self) -> np.ndarray:
        return np.frombuffer(self.dec_data, dtype=np.uint8).reshape(tuple(self.dec_shape))