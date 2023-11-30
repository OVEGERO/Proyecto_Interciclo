from .cuda_context import CudaContext
from pycuda.compiler import SourceModule
import numpy as np
import pycuda.driver as drv
import random
import base64
import re


class RsaEncryptGpu():


    def get_power_2_factors(self, n: int) -> (int, int):
        r, d = 0, n
        while d % 2 == 0:
            d //= 2
            r += 1
        return r, d


    def miller_rabin_prime_test_cuda(n: int, k: int, d: int, r: int) -> bool:

        if CudaContext.initialized:
            CudaContext.pop_context()

        CudaContext.get_context()

        try:
            rsa_kernel = """

            __device__ int powerMod(long long a, long long b, long long m) {
                long long result = 1;
                long long x = a % m;

                for (int i = 1; i <= b; i <<= 1) {
                    if ((b & i) != 0) {
                        result = (result * x) % m;
                    }
                    x = (x * x) % m;
                }
                return result;
            }

            __global__ void millerRabinKernel(long long n, int k, long long d, long long r, bool* isPrimeArray) {
                int idx = threadIdx.x + blockIdx.x * blockDim.x;
                if (idx >= k) return;

                long long a = 2 + idx;
                long long x = powerMod(a, d, n);
                
                if (x == 1 || x == n - 1) {
                    isPrimeArray[idx] = true;
                    return;
                }

                int powerOf2 = 1;
                for (int i = 0; i < r - 1; i++) {
                    x = powerMod(a, d * powerOf2, n);
                    if (x == n - 1) {
                        isPrimeArray[idx] = true;
                        return;
                    }
                    powerOf2 *= 2;
                }

                isPrimeArray[idx] = false;
            }

        """
            mod = SourceModule(rsa_kernel)
            miller_rabin_kernel = mod.get_function("millerRabinKernel")
            is_prime_array = np.zeros(k, dtype=bool)
            miller_rabin_kernel(
                np.int64(n),
                np.int64(k),
                np.int64(d),
                np.int64(r),
                drv.Out(is_prime_array),
                block=(1024, 1, 1),
                grid=(1, 1, 1)
            )
            drv.Context.synchronize()
            return np.all(is_prime_array)
        finally:
            CudaContext.pop_context()


    def generate_prime_number_gpu(self, bit_length: int) -> int:
        low, high = 2**(bit_length - 1), 2**bit_length - 1

        while True:
            candidate = random.randrange(low, high)
            r, d = self.get_power_2_factors(self, candidate - 1)
            if candidate % 2 != 0 and self.miller_rabin_prime_test_cuda(candidate, 64, d, r):
                return candidate


    def extended_gcd(self, a, b):
        if not b:
            return 1, 0
        u, v = self.extended_gcd(self,b, a % b)
        return v, u - v * (a // b)


    def calculate_private_key(self, e: int, p: int, q: int) -> int:
        return self.extended_gcd(self, e, (p-1)*(q-1))[0]


    def rsa_encrypt_blockwise(self, plaintext_bytes, e, n):
        block_size = (n.bit_length() + 7) // 8 - 1
        return b''.join(pow(int.from_bytes(plaintext_bytes[i:i + block_size], "big"), e, n).to_bytes((n.bit_length() + 7) // 8, 'big') for i in range(0, len(plaintext_bytes), block_size))


    def rsa_decrypt_blockwise(self, ciphertext, d, n):
        block_size = (n.bit_length() + 7) // 8
        return b''.join(pow(int.from_bytes(ciphertext[i:i + block_size], "big"), d, n).to_bytes(block_size, 'big') for i in range(0, len(ciphertext), block_size)).rstrip(b'\x00')


    def encrypt(self, plaintext, rsa_key_size, public_key):

        e = 65537
        if public_key == None or public_key == '':
            prime_number_bit_length = rsa_key_size // 2
            # Generate prime numbers p and q
            p = self.generate_prime_number_gpu(self, prime_number_bit_length)
            q = self.generate_prime_number_gpu(self, prime_number_bit_length)

            # Calculate public key
            n = p * q

            # Calculate private key
            d = self.calculate_private_key(self, e, p, q)
            ciphertext = self.rsa_encrypt_blockwise(self, plaintext.encode(), e, n)

            encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')

            return {
                'ciphertext': encoded_ciphertext,
                'd': str(d),
                'n': str(n)
            }
        
        else:
            n = public_key
            ciphertext = base64.b64decode(plaintext)
            ciphertext = self.rsa_encrypt_blockwise(self, plaintext.encode(), e, n)
            encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
            return {
                'ciphertext': encoded_ciphertext,
                'd': 0,
                'n': 0
            }

    
    def decrypt(self, ciphertext, d, n):
        try:
            recovered_plaintext_bytes = self.rsa_decrypt_blockwise(self, ciphertext, d, n)
            recovered_plaintext = recovered_plaintext_bytes.decode('utf-8')
            recovered_plaintext = re.sub(r'\x00', '', recovered_plaintext)
            if recovered_plaintext == '':
                return 'Error al desencriptar el mensaje'
            else:
                return recovered_plaintext
        except:
            return 'Error al desencriptar el mensaje'
