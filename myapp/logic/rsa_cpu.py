import os
import re
import base64

class RsaEncryptCpu():


    """
        Obtiene la cantidad de factores de potencia de 2 y el número restante después de dividir por potencias de 2.
    """
    def get_power_2_factors(self, n: int) -> (int, int):
        r = 0
        d = n
        while n > 0 and d % 2 == 0:
            d = d // 2
            r += 1
        return r, d


    """
        Realiza el test de primalidad de Miller-Rabin para verificar si un número es probablemente primo.
    """
    def miller_rabin_prime_test(self, n: int, k: int) -> bool:

        # Factor powers of 2 from n - 1 s.t. n - 1 = 2^r * d
        r, d = self.get_power_2_factors(self, n-1)

        for i in range(k):
            a = self.get_random_bits(self, n.bit_length())
            while a not in range(2, n-2+1):
                a = self.get_random_bits(self, n.bit_length())
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            n_1_found = False
            for j in range(r-1):
                x = pow(x, 2, n)
                if x == n - 1:
                    n_1_found = True
                    break
            if not n_1_found:
                return False
        return True


    """
        Genera un número aleatorio con la longitud de bits especificada.
    """
    def get_random_bits(self, bit_length: int) -> int:
        return int.from_bytes(os.urandom((bit_length + 7) // 8), 'big')



    """
        Genera un número primo aleatorio dentro de un rango específico.
    """
    def generate_prime_number(self, bit_length: int) -> int:

        # prime needs to be in range [2^(n-1), 2^n-1]
        low = pow(2, bit_length - 1)
        high = pow(2, bit_length) - 1

        while True:

            # Generate odd prime candidate in range
            candidate_prime = self.get_random_bits(self, bit_length)
            while candidate_prime not in range(low, high+1) or not candidate_prime % 2:
                candidate_prime = self.get_random_bits(self, bit_length)

            # with k rounds, miller rabin test gives false positive with probability (1/4)^k = 1/(2^2k)
            k = 64
            if self.miller_rabin_prime_test(self, candidate_prime, k):
                return candidate_prime


    """
        Calcula el máximo común divisor extendido de dos números.
    """
    def extended_gcd(self, a, b):
        if not b:
            return 1, 0

        u, v = self.extended_gcd(self, b, a % b)
        return v, u - v * (a // b)


    """
        Calcula la clave privada para RSA.
    """
    def calculate_private_key(self, e: int, p: int, q: int) -> int:
        u, _ = self.extended_gcd(self, e, (p-1)*(q-1))
        return u



    """
        Realiza el cifrado RSA de manera bloqueada sobre los bytes del texto plano.
    """
    def rsa_encrypt_blockwise(self, plaintext_bytes, e, n):
        block_size = (n.bit_length() + 7) // 8 - 1
        ciphertext_blocks = []

        for i in range(0, len(plaintext_bytes), block_size):
            block = plaintext_bytes[i:i + block_size]
            block_int = int.from_bytes(block, "big")
            encrypted_block_int = pow(block_int, e, n)
            ciphertext_blocks.append(encrypted_block_int.to_bytes((n.bit_length() + 7) // 8, 'big'))

        return b''.join(ciphertext_blocks)


    """
        Realiza el descifrado RSA de manera bloqueada sobre el texto cifrado.
    """
    def rsa_decrypt_blockwise(self, ciphertext, d, n):
        block_size = (n.bit_length() + 7) // 8
        plaintext_blocks = []

        for i in range(0, len(ciphertext), block_size):
            block = ciphertext[i:i + block_size]
            block_int = int.from_bytes(block, "big")
            decrypted_block_int = pow(block_int, d, n)
            plaintext_blocks.append(decrypted_block_int.to_bytes(block_size, 'big'))

        return b''.join(plaintext_blocks).rstrip(b'\x00')


    """
        Función principal para cifrar el texto plano utilizando RSA.
    """
    def encrypt(self, plaintext, rsa_key_size, public_key):

        e = 65537
        if public_key == None or public_key == '':
            prime_number_bit_length = rsa_key_size // 2
            # Generate prime numbers p and q
            p = self.generate_prime_number(self, prime_number_bit_length)
            q = self.generate_prime_number(self, prime_number_bit_length)

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

    
    """
        Función para descifrar el texto cifrado utilizando RSA.
    """
    def decrypt(self, ciphertext, d, n):
        recovered_plaintext_bytes = self.rsa_decrypt_blockwise(self, ciphertext, d, n)
        recovered_plaintext = recovered_plaintext_bytes.decode('utf-8')
        recovered_plaintext = re.sub(r'\x00', '', recovered_plaintext)
        return recovered_plaintext