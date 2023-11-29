
<!-- TITULO -->
# Backend - API REST en Django
### Proyecto de criptografía utilizando RSA y AES

<!-- DESCRIPCION -->
### Pasos para ejecutar el proyecto de manera local

1. Clonar el repositorio
```sh
git clone
```
2. Crear un entorno virtual
```sh
python -m venv venv
```
3. Activar el entorno virtual
```sh
venv\Scripts\activate
```
4. Instalar las dependencias
```sh
pip install -r requirements.txt
```
5. Ejecutar el proyecto
```sh
python manage.py runserver
```
6. Abrir el navegador en la siguiente dirección
```sh
http://127.0.0.1:8000/
```
7. Endpoints
```sh
http://127.0.0.1:8000/cryptography/encrypt
http://127.0.0.1:8000/cryptography/decrypt
```
8. Revisar el proyecto para más información sobre los endpoints

### Estructura del proyecto
    
    ├── myapp
    │   ├── logic
    │   │   ├──aes_cpu.py        # Lógica para cifrar y descifrar con AES con CPU
    │   │   ├──aes_gpu.py        # Lógica para cifrar y descifrar con AES con GPU
    │   │   ├──cuda_context.py   # Lógica para crear el contexto de CUDA
    │   │   ├──global_encrypt.py # Lógica para determinar el tipo de cifrado
    │   │   ├──rsa_cpu.py        # Lógica para cifrar y descifrar con RSA con CPU
    │   │   └──rsa_gpu.py        # Lógica para cifrar y descifrar con RSA con GPU
    │   ├── __init__.py          # Archivo de inicialización   
    │   ├── admin.py             # Archivo de configuración del administrador
    │   ├── apps.py              # Archivo de configuración de la aplicación
    │   ├── models.py            # Archivo de configuración de los modelos
    │   ├── tests.py             # Archivo de configuración de las pruebas
    │   ├── urls.py              # Archivo de configuración de las urls
    │   └── views.py             # Archivo de configuración de las vista
    ├── mysite
    │   ├── __init__.py          # Archivo de inicialización
    │   ├── asgi.py              # Archivo de configuración de ASGI
    │   ├── settings.py          # Archivo de configuración de las variables de entorno
    │   ├── urls.py              # Archivo de configuración de las urls
    │   └── wsgi.py              # Archivo de configuración de WSGI
    ├── manage.py                # Archivo de configuración de Django
    ├── requirements.txt         # Archivo de dependencias
    ├── .gitignore               # Archivo de configuración de Git
    └── README.md                # Archivo de descripción del proyecto

