{\rtf1\ansi\ansicpg1252\cocoartf2868
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 # ============================================================\
# Escenario 1: Tokenizaci\'f3n y Cifrado de PAN con AES-256-GCM\
# Librer\'edas requeridas:\
#   pip install pycryptodome boto3\
# ============================================================\
\
import os\
import uuid\
import hmac\
from typing import Tuple\
\
import boto3\
from Crypto.Cipher import AES\
from Crypto.Protocol.KDF import PBKDF2\
from Crypto.Hash import SHA256\
\
\
# ============================================================\
# CONFIGURACI\'d3N CRIPTOGR\'c1FICA\
# ============================================================\
\
SALT_SIZE   = 16        # 128 bits\
NONCE_SIZE  = 12        # 96 bits recomendado para GCM\
TAG_SIZE    = 16        # 128 bits\
PBKDF2_ITER = 600_000   # OWASP 2024\
KEY_LEN     = 32        # AES-256 = 32 bytes\
\
AWS_REGION = 'us-east-1'\
\
# Reemplazar con tu CMK real\
CMK_KEY_ID = 'arn:aws:kms:us-east-1:123456789:key/YOUR-CMK-ID'\
\
\
# ============================================================\
# CLIENTE AWS KMS\
# ============================================================\
\
kms_client = boto3.client(\
    'kms',\
    region_name=AWS_REGION\
)\
\
\
# ============================================================\
# FUNCIONES KMS\
# ============================================================\
\
def get_data_encryption_key() -> Tuple[bytes, bytes]:\
    """\
    Solicita una DEK (Data Encryption Key) a AWS KMS.\
\
    Retorna:\
        (dek_plaintext, dek_encrypted)\
\
    - dek_plaintext:\
        Solo existe en memoria RAM temporalmente.\
\
    - dek_encrypted:\
        Se almacena en base de datos.\
    """\
\
    response = kms_client.generate_data_key(\
        KeyId=CMK_KEY_ID,\
        KeySpec='AES_256'\
    )\
\
    dek_plaintext = response['Plaintext']\
    dek_encrypted = response['CiphertextBlob']\
\
    return dek_plaintext, dek_encrypted\
\
\
# ============================================================\
# DERIVACI\'d3N DE CLAVE OPERACIONAL\
# ============================================================\
\
def derive_operational_key(\
    dek_plaintext: bytes,\
    salt: bytes\
) -> bytes:\
    """\
    Deriva una clave operacional usando PBKDF2-SHA256.\
    """\
\
    return PBKDF2(\
        password=dek_plaintext,\
        salt=salt,\
        dkLen=KEY_LEN,\
        count=PBKDF2_ITER,\
        prf=lambda p, s: hmac.new(p, s, SHA256).digest()\
    )\
\
\
# ============================================================\
# CIFRADO DE PAN\
# ============================================================\
\
def encrypt_pan(pan: str) -> dict:\
    """\
    Cifra un PAN usando AES-256-GCM.\
\
    Retorna un diccionario listo para almacenar en Vault DB.\
    """\
\
    # --------------------------------------------------------\
    # 1. Obtener DEK desde AWS KMS\
    # --------------------------------------------------------\
\
    dek_plaintext, dek_encrypted = get_data_encryption_key()\
\
    try:\
\
        # ----------------------------------------------------\
        # 2. Generar salt y nonce seguros\
        # ----------------------------------------------------\
\
        salt = os.urandom(SALT_SIZE)\
        nonce = os.urandom(NONCE_SIZE)\
\
        # ----------------------------------------------------\
        # 3. Derivar clave operacional\
        # ----------------------------------------------------\
\
        op_key = derive_operational_key(\
            dek_plaintext,\
            salt\
        )\
\
        # ----------------------------------------------------\
        # 4. AES-256-GCM\
        # ----------------------------------------------------\
\
        cipher = AES.new(\
            op_key,\
            AES.MODE_GCM,\
            nonce=nonce\
        )\
\
        ciphertext, tag = cipher.encrypt_and_digest(\
            pan.encode('utf-8')\
        )\
\
        # ----------------------------------------------------\
        # 5. Token UUID v4\
        # ----------------------------------------------------\
\
        token = str(uuid.uuid4())\
\
        # ----------------------------------------------------\
        # 6. Retornar registro para Vault DB\
        # ----------------------------------------------------\
\
        return \{\
            'token': token,\
            'ciphertext': ciphertext.hex(),\
            'nonce': nonce.hex(),\
            'tag': tag.hex(),\
            'salt': salt.hex(),\
            'dek_encrypted': dek_encrypted.hex()\
        \}\
\
    finally:\
\
        # ----------------------------------------------------\
        # 7. Destruir material sensible\
        # ----------------------------------------------------\
\
        del dek_plaintext\
        del op_key\
\
\
# ============================================================\
# DESCIFRADO DE PAN\
# ============================================================\
\
def decrypt_pan(vault_record: dict) -> str:\
    """\
    Descifra el PAN desde Vault DB.\
    """\
\
    # --------------------------------------------------------\
    # 1. Recuperar DEK desde KMS\
    # --------------------------------------------------------\
\
    response = kms_client.decrypt(\
        CiphertextBlob=bytes.fromhex(\
            vault_record['dek_encrypted']\
        )\
    )\
\
    dek_plaintext = response['Plaintext']\
\
    try:\
\
        # ----------------------------------------------------\
        # 2. Derivar misma clave operacional\
        # ----------------------------------------------------\
\
        salt = bytes.fromhex(vault_record['salt'])\
\
        op_key = derive_operational_key(\
            dek_plaintext,\
            salt\
        )\
\
        # ----------------------------------------------------\
        # 3. Reconstruir nonce\
        # ----------------------------------------------------\
\
        nonce = bytes.fromhex(vault_record['nonce'])\
\
        # ----------------------------------------------------\
        # 4. Descifrar y verificar integridad\
        # ----------------------------------------------------\
\
        cipher = AES.new(\
            op_key,\
            AES.MODE_GCM,\
            nonce=nonce\
        )\
\
        pan = cipher.decrypt_and_verify(\
            bytes.fromhex(vault_record['ciphertext']),\
            bytes.fromhex(vault_record['tag'])\
        )\
\
        return pan.decode('utf-8')\
\
    finally:\
\
        del dek_plaintext\
        del op_key\
\
\
# ============================================================\
# DEMOSTRACI\'d3N\
# ============================================================\
\
if __name__ == '__main__':\
\
    # PAN de prueba\
    pan_original = '4532015112830366'\
\
    print('\\n==============================')\
    print('TOKENIZACI\'d3N AES-256-GCM')\
    print('==============================\\n')\
\
    print(f'PAN original: \{pan_original\}')\
\
    # --------------------------------------------------------\
    # Cifrado\
    # --------------------------------------------------------\
\
    vault_record = encrypt_pan(pan_original)\
\
    print('\\n--- DATOS ALMACENADOS ---')\
    print(f'Token:        \{vault_record["token"]\}')\
    print(f'Ciphertext:   \{vault_record["ciphertext"][:40]\}...')\
    print(f'Nonce:        \{vault_record["nonce"]\}')\
    print(f'Auth Tag:     \{vault_record["tag"]\}')\
    print(f'Salt:         \{vault_record["salt"]\}')\
\
    # --------------------------------------------------------\
    # Descifrado\
    # --------------------------------------------------------\
\
    pan_descifrado = decrypt_pan(vault_record)\
\
    print('\\n--- DESCIFRADO ---')\
    print(f'PAN recuperado: \{pan_descifrado\}')\
\
    # --------------------------------------------------------\
    # Validaci\'f3n\
    # --------------------------------------------------------\
\
    assert pan_descifrado == pan_original, (\
        'ERROR: Integridad fallida'\
    )\
\
    print('\\n\uc0\u10003  Integridad verificada con AES-256-GCM')}