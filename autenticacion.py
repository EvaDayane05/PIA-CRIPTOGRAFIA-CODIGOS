{\rtf1\ansi\ansicpg1252\cocoartf2868
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 # ============================================================\
# Escenario 3: Autenticaci\'f3n Robusta con Scrypt + Timing-Safe\
# Librer\'edas:\
#   hashlib (Scrypt nativo Python 3.9+)\
#   hmac\
#   os\
# ============================================================\
\
import os\
import hmac\
import hashlib\
import time\
\
from dataclasses import dataclass\
\
\
# ============================================================\
# PAR\'c1METROS SCRYPT\
# ============================================================\
\
# N:\
# Factor de costo (potencia de 2)\
# Mayor N = m\'e1s CPU y memoria\
\
SCRYPT_N = 2**20       # Producci\'f3n (~1s)\
SCRYPT_N_DEV = 2**14   # Desarrollo (~70 ms)\
\
# r:\
# Tama\'f1o de bloque\
\
SCRYPT_R = 8\
\
# p:\
# Paralelizaci\'f3n\
\
SCRYPT_P = 1\
\
# Salt aleatorio\
\
SALT_SIZE = 16         # 128 bits\
\
# Longitud del hash derivado\
\
HASH_LEN = 64          # 512 bits\
\
\
# ============================================================\
# MODELO DE PASSWORD\
# ============================================================\
\
@dataclass\
class PasswordRecord:\
    """\
    Registro seguro almacenado en BD.\
    """\
\
    salt_hex: str\
    hash_hex: str\
    n_param: int\
\
\
# ============================================================\
# HASH DE CONTRASE\'d1A\
# ============================================================\
\
def hash_password(\
    password: str,\
    use_dev_params: bool = False\
) -> PasswordRecord:\
    """\
    Genera hash Scrypt seguro.\
    """\
\
    # --------------------------------------------------------\
    # 1. Salt aleatorio criptogr\'e1fico\
    # --------------------------------------------------------\
\
    salt = os.urandom(SALT_SIZE)\
\
    # --------------------------------------------------------\
    # 2. Par\'e1metros seg\'fan entorno\
    # --------------------------------------------------------\
\
    n = SCRYPT_N_DEV if use_dev_params else SCRYPT_N\
\
    # --------------------------------------------------------\
    # 3. Derivaci\'f3n Scrypt\
    # --------------------------------------------------------\
\
    hash_bytes = hashlib.scrypt(\
        password=password.encode('utf-8'),\
        salt=salt,\
        n=n,\
        r=SCRYPT_R,\
        p=SCRYPT_P,\
        dklen=HASH_LEN\
    )\
\
    # --------------------------------------------------------\
    # 4. Retornar registro\
    # --------------------------------------------------------\
\
    return PasswordRecord(\
        salt_hex=salt.hex(),\
        hash_hex=hash_bytes.hex(),\
        n_param=n\
    )\
\
\
# ============================================================\
# VERIFICACI\'d3N DE PASSWORD\
# ============================================================\
\
def verify_password(\
    password: str,\
    record: PasswordRecord\
) -> bool:\
    """\
    Verifica password usando comparaci\'f3n timing-safe.\
    """\
\
    # --------------------------------------------------------\
    # 1. Recuperar salt\
    # --------------------------------------------------------\
\
    salt = bytes.fromhex(record.salt_hex)\
\
    # --------------------------------------------------------\
    # 2. Recalcular hash\
    # --------------------------------------------------------\
\
    candidate_hash = hashlib.scrypt(\
        password=password.encode('utf-8'),\
        salt=salt,\
        n=record.n_param,\
        r=SCRYPT_R,\
        p=SCRYPT_P,\
        dklen=HASH_LEN\
    )\
\
    # --------------------------------------------------------\
    # 3. Comparaci\'f3n timing-safe\
    # --------------------------------------------------------\
\
    return hmac.compare_digest(\
        candidate_hash,\
        bytes.fromhex(record.hash_hex)\
    )\
\
\
# ============================================================\
# DEMOSTRACI\'d3N TIMING-SAFE\
# ============================================================\
\
def demonstrate_timing_safety():\
    """\
    Demuestra resistencia a timing attacks.\
    """\
\
    record = hash_password(\
        'mi_password_secreto',\
        use_dev_params=True\
    )\
\
    # --------------------------------------------------------\
    # Password incorrecta\
    # --------------------------------------------------------\
\
    t0 = time.perf_counter()\
\
    result_wrong = verify_password(\
        'password_incorrecto',\
        record\
    )\
\
    t_wrong = time.perf_counter() - t0\
\
    # --------------------------------------------------------\
    # Password correcta\
    # --------------------------------------------------------\
\
    t0 = time.perf_counter()\
\
    result_correct = verify_password(\
        'mi_password_secreto',\
        record\
    )\
\
    t_correct = time.perf_counter() - t0\
\
    # --------------------------------------------------------\
    # Mostrar tiempos\
    # --------------------------------------------------------\
\
    print(\
        f'Tiempo incorrecta: '\
        f'\{t_wrong * 1000:.1f\} ms '\
        f'\uc0\u8594  \{result_wrong\}'\
    )\
\
    print(\
        f'Tiempo correcta:   '\
        f'\{t_correct * 1000:.1f\} ms '\
        f'\uc0\u8594  \{result_correct\}'\
    )\
\
    print(\
        '\uc0\u8594  compare_digest es timing-safe'\
    )\
\
\
# ============================================================\
# DEMOSTRACI\'d3N PRINCIPAL\
# ============================================================\
\
if __name__ == '__main__':\
\
    print('\\n==============================')\
    print('REGISTRO DE USUARIO')\
    print('==============================\\n')\
\
    # --------------------------------------------------------\
    # Registro de usuario\
    # --------------------------------------------------------\
\
    record = hash_password(\
        'Contrase$a_B4ncari4_S3gura!',\
        use_dev_params=True\
    )\
\
    print(f'Salt (hex):  \{record.salt_hex\}')\
\
    print(\
        f'Hash:        '\
        f'\{record.hash_hex[:64]\}...'\
    )\
\
    print(\
        f'N Param:     '\
        f'\{record.n_param\}'\
    )\
\
    print(\
        '\\nGuardado en BD: '\
        'salt + hash + n_param'\
    )\
\
    print(\
        '(NUNCA la contrase\'f1a)'\
    )\
\
    # --------------------------------------------------------\
    # Login correcto / incorrecto\
    # --------------------------------------------------------\
\
    print('\\n==============================')\
    print('VERIFICACI\'d3N LOGIN')\
    print('==============================\\n')\
\
    correcta = verify_password(\
        'Contrase$a_B4ncari4_S3gura!',\
        record\
    )\
\
    incorrecta = verify_password(\
        'password123',\
        record\
    )\
\
    print(f'Contrase\'f1a correcta:   \{correcta\}')\
    print(f'Contrase\'f1a incorrecta: \{incorrecta\}')\
\
    # --------------------------------------------------------\
    # Timing-safe\
    # --------------------------------------------------------\
\
    print('\\n==============================')\
    print('PRUEBA TIMING-SAFE')\
    print('==============================\\n')\
\
    demonstrate_timing_safety()\
\
    # --------------------------------------------------------\
    # Resistencia criptogr\'e1fica\
    # --------------------------------------------------------\
\
    print('\\n==============================')\
    print('RESISTENCIA A ATAQUES')\
    print('==============================\\n')\
\
    print(\
        'N=2^20 requiere ~1GB RAM '\
        'y ~1s por intento'\
    )\
\
    print(\
        'GPUs/ASICs siguen siendo '\
        'costosos por memory-hard'\
    )\
\
    print(\
        'Scrypt reduce efectividad '\
        'de ataques paralelos'\
    )}