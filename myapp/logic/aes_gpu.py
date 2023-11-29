from .cuda_context import CudaContext
from pycuda.compiler import SourceModule
import numpy as np
import pycuda.driver as drv
import os
import base64

class AesEncryptGpu():

    @staticmethod
    def get_s_box(self):
        s_box_string = '63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76' \
                    'ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0' \
                    'b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15' \
                    '04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75' \
                    '09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84' \
                    '53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf' \
                    'd0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8' \
                    '51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2' \
                    'cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73' \
                    '60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db' \
                    'e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79' \
                    'e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08' \
                    'ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a' \
                    '70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e' \
                    'e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df' \
                    '8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16'.replace(" ", "")
        s_box = bytearray.fromhex(s_box_string)
        return s_box


    @staticmethod
    def get_inv_s_box(self):
        inv_s_box_string = '52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb' \
                        '7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb' \
                        '54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e' \
                        '08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25' \
                        '72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92' \
                        '6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84' \
                        '90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06' \
                        'd0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b' \
                        '3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73' \
                        '96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e' \
                        '47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b' \
                        'fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4' \
                        '1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f' \
                        '60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef' \
                        'a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61' \
                        '17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d'.replace(" ", "")
        inv_s_box = bytearray.fromhex(inv_s_box_string)
        return inv_s_box


    @staticmethod
    def generate_secure_key(length):
        return os.urandom(length)


    @staticmethod
    def pad(data):
        length = 16 - (len(data) % 16)
        return data + bytes([length] * length)


    @staticmethod
    def unpad(data):
        return data[:-data[-1]]


    @staticmethod
    def xor_blocks(block1, block2):
        return bytes(a ^ b for a, b in zip(block1, block2))


    def sub_word(self, word: [int]) -> bytes:
        s_box = self.get_s_box(self)
        substituted_word = bytes(s_box[i] for i in word)
        return substituted_word


    def rcon(self, i: int) -> bytes:
        # From Wikipedia
        rcon_lookup = bytearray.fromhex('01020408102040801b36')
        rcon_value = bytes([rcon_lookup[i-1], 0, 0, 0])
        return rcon_value


    def xor_bytes(self, a: bytes, b: bytes) -> bytes:
        return bytes([x ^ y for (x, y) in zip(a, b)])


    def rot_word(self, word: [int]) -> [int]:
        return word[1:] + word[:1]


    def key_expansion(self, key: bytes, nb: int = 4) -> [[[int]]]:

        nk = len(key) // 4

        key_bit_length = len(key) * 8

        if key_bit_length == 128:
            nr = 10
        elif key_bit_length == 192:
            nr = 12
        else:  # 256-bit keys
            nr = 14

        w = self.state_from_bytes(self, key)

        for i in range(nk, nb * (nr + 1)):
            temp = w[i-1]
            if i % nk == 0:
                temp = self.xor_bytes(self, self.sub_word(self, self.rot_word(self, temp)), self.rcon(self, i // nk))
            elif nk > 6 and i % nk == 4:
                temp = self.sub_word(self, temp)
            w.append(self.xor_bytes(self, w[i - nk], temp))

        return [w[i*4:(i+1)*4] for i in range(len(w) // 4)]


    # PARALELIZABLE
    def shift_rows(self, state: [[int]]):
        # [00, 10, 20, 30]     [00, 10, 20, 30]
        # [01, 11, 21, 31] --> [11, 21, 31, 01]
        # [02, 12, 22, 32]     [22, 32, 02, 12]
        # [03, 13, 23, 33]     [33, 03, 13, 23]
        state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
        state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
        state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]


    def xtime(self, a: int) -> int:
        if a & 0x80:
            return ((a << 1) ^ 0x1b) & 0xff
        return a << 1


    def mix_column(self, col: [int]):
        c_0 = col[0]
        all_xor = col[0] ^ col[1] ^ col[2] ^ col[3]
        col[0] ^= all_xor ^ self.xtime(self, col[0] ^ col[1])
        col[1] ^= all_xor ^ self.xtime(self, col[1] ^ col[2])
        col[2] ^= all_xor ^ self.xtime(self, col[2] ^ col[3])
        col[3] ^= all_xor ^ self.xtime(self, c_0 ^ col[3])


    # PARALELIZABLE
    def mix_columns(self, state: [[int]]):
        for r in state:
            self.mix_column(self, r)


    def state_from_bytes(self, data: bytes) -> [[int]]:
        state = [data[i*4:(i+1)*4] for i in range(len(data) // 4)]
        return state


    def bytes_from_state(self, state: [[int]]) -> bytes:
        return bytes(state[0] + state[1] + state[2] + state[3])


    def aes_encrypt_cbc(self, text, key, iv):
        padded_text = self.pad(text.encode())  # Asegúrate de que el texto esté rellenado
        blocks = [padded_text[i:i+16] for i in range(0, len(padded_text), 16)]

        encrypted_blocks = []
        previous_block = iv
        for block in blocks:
            block_to_encrypt = self.xor_blocks(block, previous_block)
            encrypted_block = self.aes_encryption(self, block_to_encrypt, key)
            encrypted_blocks.append(encrypted_block)
            previous_block = encrypted_block

        return b''.join(encrypted_blocks)


    def aes_decrypt_cbc(self, encrypted_text, key, iv):
        blocks = [encrypted_text[i:i+16] for i in range(0, len(encrypted_text), 16)]

        decrypted_blocks = []
        previous_block = iv
        for block in blocks:
            decrypted_block = self.aes_decryption(self, block, key)
            decrypted_text_block = self.xor_blocks(decrypted_block, previous_block)
            decrypted_blocks.append(decrypted_text_block)
            previous_block = block

        decrypted_text = b''.join(decrypted_blocks)
        return self.unpad(decrypted_text).decode()


    def aes_encryption(self, data: bytes, key: bytes) -> bytes:

        if CudaContext.initialized:
            CudaContext.pop_context()

        CudaContext.get_context()

        try:
            aes_kernels = """

                __global__ void subBytesKernel(unsigned char *state, const unsigned char *s_box) {
                    int idx = blockIdx.x * blockDim.x + threadIdx.x;
                    if (idx < 16) {  // Asegurando que solo se procesen 16 bytes (tamaño del estado en AES)
                        state[idx] = s_box[state[idx]];
                    }
                }

                __global__ void addRoundKeyKernel(unsigned char *state, unsigned char *key_schedule, int round) {
                    int idx = blockIdx.x * blockDim.x + threadIdx.x; // Índice lineal para cada byte del estado

                    if (idx < 16) { // Aseguramos que solo procesamos los 16 bytes del estado
                        int round_key_idx = round * 16 + idx;
                        state[idx] ^= key_schedule[round_key_idx];
                    }
                }

            """
            mod = SourceModule(aes_kernels)
            subBytesKernel = mod.get_function("subBytesKernel")
            addRoundKeyKernel = mod.get_function("addRoundKeyKernel")

            key_bit_length = len(key) * 8

            if key_bit_length == 128:
                nr = 10
            elif key_bit_length == 192:
                nr = 12
            else:  # 256-bit keys
                nr = 14

            state = self.state_from_bytes(self, data)
            flat_state = [byte for row in state for byte in row]
            state_np = np.array(flat_state, dtype=np.uint8)

            key_schedule = self.key_expansion(self, key)
            flattened_key_schedule = [byte for round_key in key_schedule for row in round_key for byte in row]
            key_schedule_np = np.array(flattened_key_schedule, dtype=np.uint8)

            addRoundKeyKernel(
                drv.InOut(state_np),
                drv.In(key_schedule_np),
                np.int32(0),
                block=(16, 1, 1),
                grid=(1, 1)
            )

            s_box_np = np.array(self.get_s_box(self), dtype=np.uint8)

            for round in range(1, nr):
                subBytesKernel(
                    drv.InOut(state_np),
                    drv.In(s_box_np),
                    block=(16, 1, 1),
                    grid=(1, 1)
                )
                drv.Context.synchronize()
                self.shift_rows(self, state_np.reshape(4, 4))
                self.mix_columns(self, state_np.reshape(4, 4))
                addRoundKeyKernel(
                    drv.InOut(state_np),
                    drv.In(key_schedule_np),
                    np.int32(round),
                    block=(16, 1, 1),
                    grid=(1, 1)
                )

            subBytesKernel(
                drv.InOut(state_np),
                drv.In(s_box_np),
                block=(16, 1, 1),
                grid=(1, 1)
            )
            drv.Context.synchronize()
            self.shift_rows(self, state_np.reshape(4, 4))
            addRoundKeyKernel(
                drv.InOut(state_np),
                drv.In(key_schedule_np),
                np.int32(nr),
                block=(16, 1, 1),
                grid=(1, 1)
            )

            cipher_gpu = self.bytes_from_state(self, state_np.reshape(4, 4).tolist())

            return cipher_gpu
        finally:
            CudaContext.pop_context()



    def inv_shift_rows(self, state: [[int]]) -> [[int]]:
        # [00, 10, 20, 30]     [00, 10, 20, 30]
        # [01, 11, 21, 31] <-- [11, 21, 31, 01]
        # [02, 12, 22, 32]     [22, 32, 02, 12]
        # [03, 13, 23, 33]     [33, 03, 13, 23]
        state[1][1], state[2][1], state[3][1], state[0][1] = state[0][1], state[1][1], state[2][1], state[3][1]
        state[2][2], state[3][2], state[0][2], state[1][2] = state[0][2], state[1][2], state[2][2], state[3][2]
        state[3][3], state[0][3], state[1][3], state[2][3] = state[0][3], state[1][3], state[2][3], state[3][3]
        return


    def xtimes_0e(self, b):
        # 0x0e = 14 = b1110 = ((x * 2 + x) * 2 + x) * 2
        return self.xtime(self, self.xtime(self, self.xtime(self, b) ^ b) ^ b)


    def xtimes_0b(self, b):
        # 0x0b = 11 = b1011 = ((x*2)*2+x)*2+x
        return self.xtime(self, self.xtime(self, self.xtime(self, b)) ^ b) ^ b


    def xtimes_0d(self, b):
        # 0x0d = 13 = b1101 = ((x*2+x)*2)*2+x
        return self.xtime(self, self.xtime(self, self.xtime(self, b) ^ b)) ^ b


    def xtimes_09(self, b):
        # 0x09 = 9  = b1001 = ((x*2)*2)*2+x
        return self.xtime(self, self.xtime(self, self.xtime(self, b))) ^ b


    def inv_mix_column(self, col: [int]):
        c_0, c_1, c_2, c_3 = col[0], col[1], col[2], col[3]
        col[0] = self.xtimes_0e(self, c_0) ^ self.xtimes_0b(self, c_1) ^ self.xtimes_0d(self, c_2) ^ self.xtimes_09(self, c_3)
        col[1] = self.xtimes_09(self, c_0) ^ self.xtimes_0e(self, c_1) ^ self.xtimes_0b(self, c_2) ^ self.xtimes_0d(self, c_3)
        col[2] = self.xtimes_0d(self, c_0) ^ self.xtimes_09(self, c_1) ^ self.xtimes_0e(self, c_2) ^ self.xtimes_0b(self, c_3)
        col[3] = self.xtimes_0b(self, c_0) ^ self.xtimes_0d(self, c_1) ^ self.xtimes_09(self, c_2) ^ self.xtimes_0e(self, c_3)


    def inv_mix_columns(self, state: [[int]]) -> [[int]]:
        for r in state:
            self.inv_mix_column(self, r)


    def aes_decryption(self, cipher: bytes, key: bytes) -> bytes:

        if CudaContext.initialized:
            CudaContext.pop_context()

        CudaContext.get_context()

        try:
            aes_kernels = """

                __global__ void invSubBytesKernel(unsigned char *state, const unsigned char *inv_s_box) {
                    int idx = blockIdx.x * blockDim.x + threadIdx.x;
                    if (idx < 16) {
                        state[idx] = inv_s_box[state[idx]];
                    }
                }

                __global__ void addRoundKeyKernel(unsigned char *state, unsigned char *key_schedule, int round) {
                    int idx = blockIdx.x * blockDim.x + threadIdx.x; // Índice lineal para cada byte del estado

                    if (idx < 16) { // Aseguramos que solo procesamos los 16 bytes del estado
                        int round_key_idx = round * 16 + idx;
                        state[idx] ^= key_schedule[round_key_idx];
                    }
                }

            """
            mod = SourceModule(aes_kernels)
            addRoundKeyKernel = mod.get_function("addRoundKeyKernel")
            invSubBytesKernel = mod.get_function("invSubBytesKernel")

            key_byte_length = len(key)
            key_bit_length = key_byte_length * 8
            nk = key_byte_length // 4

            if key_bit_length == 128:
                nr = 10
            elif key_bit_length == 192:
                nr = 12
            else:  # 256-bit keys
                nr = 14

            state = self.state_from_bytes(self, cipher)
            flat_state = [byte for row in state for byte in row]
            state_np = np.array(flat_state, dtype=np.uint8)

            key_schedule = self.key_expansion(self, key)
            flattened_key_schedule = [byte for round_key in key_schedule for row in round_key for byte in row]
            key_schedule_np = np.array(flattened_key_schedule, dtype=np.uint8)

            addRoundKeyKernel(
                drv.InOut(state_np),
                drv.In(key_schedule_np),
                np.int32(nr),
                block=(16, 1, 1),
                grid=(1, 1)
            )

            inv_s_box_np = np.array(self.get_inv_s_box(self), dtype=np.uint8)

            for round in range(nr-1, 0, -1):
                self.inv_shift_rows(self, state_np.reshape(4, 4))
                invSubBytesKernel(
                    drv.InOut(state_np),
                    drv.In(inv_s_box_np),
                    block=(16, 1, 1),
                    grid=(1, 1)
                )
                addRoundKeyKernel(
                    drv.InOut(state_np),
                    drv.In(key_schedule_np),
                    np.int32(round),
                    block=(16, 1, 1),
                    grid=(1, 1)
                )
                self.inv_mix_columns(self, state_np.reshape(4, 4))

            self.inv_shift_rows(self, state_np.reshape(4, 4))
            invSubBytesKernel(
                drv.InOut(state_np),
                drv.In(inv_s_box_np),
                block=(16, 1, 1),
                grid=(1, 1)
            )
            addRoundKeyKernel(
                drv.InOut(state_np),
                drv.In(key_schedule_np),
                np.int32(0),
                block=(16, 1, 1),
                grid=(1, 1)
            )

            plain = self.bytes_from_state(self, state_np.reshape(4, 4).tolist())
            return plain
        finally:
            CudaContext.pop_context()



    def encrypt(self, plaintext, key_size, public_key, iv):

        if public_key == None or public_key == '':
            iv = os.urandom(16)   # Vector de Inicialización aleatorio
            key = self.generate_secure_key(key_size)
            ciphertext = self.aes_encrypt_cbc(self, text=plaintext, iv=iv, key=key)
            encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
            encoded_key = base64.b64encode(key).decode('utf-8')
            encoded_iv = base64.b64encode(iv).decode('utf-8')
            return {
                'ciphertext': encoded_ciphertext,
                'key': encoded_key,
                'iv': encoded_iv
            }
        else:
            ciphertext = self.aes_encrypt_cbc(self, text=plaintext, iv=iv, key=public_key)
            encoded_ciphertext = base64.b64encode(ciphertext)
            return {
                'ciphertext': encoded_ciphertext,
                'key': 0,
                'iv': 0
            }


    def decrypt(self, ciphertext, public_key, iv):
        try:
            decrypted_plaintext = self.aes_decrypt_cbc(self, encrypted_text=ciphertext, key=public_key, iv=iv)
            if decrypted_plaintext == '':
                return 'Error al desencriptar el texto.'
            else:
                return decrypted_plaintext
        except:
            return 'Error al desencriptar el texto.'
     
