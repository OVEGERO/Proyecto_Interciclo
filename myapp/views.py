from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import HttpResponse
from rest_framework import status
from .logic import global_encrypt
import base64


encrypts = global_encrypt.ChooseEncrypt()


# Create your views here.

@api_view(['POST'])
def encrypt_methods(request):
    text_to_encrypt = request.data.get('text')
    key_size = request.data.get('key_size', 0)
    public_key = request.data.get('public_key')
    encrypt_type = request.data.get('encrypt_type')
    mode = request.data.get('mode')
    iv = request.data.get('iv', 0)

    # Validaciones iniciales
    if not all([mode, encrypt_type, text_to_encrypt, key_size]):
        return Response({'error': 'Missing required fields.'}, status=status.HTTP_400_BAD_REQUEST)

    # Procesar la clave pública y el IV
    try:
        key_size = int(key_size)
        if public_key:
            if encrypt_type == 'rsa':
                public_key = int(public_key)
            elif encrypt_type == 'aes':
                public_key = base64.b64decode(public_key)
    except ValueError:
        return Response({'error': 'Invalid input for key size or public key'}, status=status.HTTP_400_BAD_REQUEST)
    
    if iv:
        try:
            iv = base64.b64decode(iv)
        except ValueError:
            return Response({'error': 'Invalid IV'}, status=status.HTTP_400_BAD_REQUEST)
        
    try:
        encryption_method = encrypts.encryption_mode(encrypt_type, mode)
        if (encrypt_type == 'rsa'):
            encrypted = encryption_method.encrypt(self=encryption_method,plaintext=text_to_encrypt, rsa_key_size=key_size, public_key=public_key)
            return Response(
                {
                    'encrypted_text': encrypted['ciphertext'],
                    'private_key': encrypted['d'],
                    'public_key': encrypted['n'],
                },
                status = status.HTTP_200_OK
            )
        elif (encrypt_type == 'aes'):
            encrypted = encryption_method.encrypt(self=encryption_method, plaintext=text_to_encrypt, key_size=key_size, public_key=public_key, iv=iv)
            return Response(
                {
                    'encrypted_text': encrypted['ciphertext'],
                    'public_key': encrypted['key'],
                    'iv': encrypted['iv'],
                },
                status = status.HTTP_200_OK
            )

    except Exception as e:
        return Response(
            {
                'error': str(e)
            },
            status = status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
@api_view(['POST'])
def decrypt_methods(request):
    text_to_decrypt = request.data.get('text')
    private_key = request.data.get('private_key', 0)
    public_key = request.data.get('public_key')
    iv = request.data.get('iv', 0)
    mode = request.data.get('mode')
    encrypt_type = request.data.get('encrypt_type')

    if not all([text_to_decrypt, public_key, encrypt_type, mode]):
        return Response({'error': 'Missing required fields.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        text_to_decrypt = base64.b64decode(text_to_decrypt)
    except ValueError:
        return Response({'error': 'Invalid input for text to decrypt'}, status=status.HTTP_400_BAD_REQUEST)

    if encrypt_type == 'rsa':
        try:
            public_key = int(public_key)
            private_key = int(private_key or 0)
        except ValueError:
            return Response({'error': 'Invalid RSA keys'}, status=status.HTTP_400_BAD_REQUEST)
    elif encrypt_type == 'aes':
        try:
            public_key = base64.b64decode(public_key)
        except ValueError:
            return Response({'error': 'Invalid AES key'}, status=status.HTTP_400_BAD_REQUEST)
        if iv:
            try:
                iv = base64.b64decode(iv)
            except ValueError:
                return Response({'error': 'Invalid IV'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'Invalid encryption type'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        decryption_method = encrypts.encryption_mode(encrypt_type, mode)
        if (encrypt_type == 'rsa'):
            decrypted = decryption_method.decrypt(self=decryption_method, ciphertext=text_to_decrypt, d=private_key, n=public_key)
        elif (encrypt_type == 'aes'):
            decrypted = decryption_method.decrypt(self=decryption_method, ciphertext=text_to_decrypt, public_key=public_key, iv=iv)
        return Response(
            {
                'decrypted_text': decrypted
            },
            status = status.HTTP_200_OK
        )
    except Exception as e:
        return Response(
            {
                'error': str(e)
            },
            status = status.HTTP_500_INTERNAL_SERVER_ERROR
        )