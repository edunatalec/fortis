# AES (Advanced Encryption Standard)

El AES es el algoritmo de criptografía simétrica más utilizado en el mundo. Es un estándar del gobierno de los Estados Unidos y es adoptado globalmente en prácticamente todos los protocolos y sistemas de seguridad modernos.

## Tabla de Contenidos

- [1. ¿Qué es AES?](#1-qué-es-aes)
- [2. Historia](#2-historia)
- [3. Cómo Funciona](#3-cómo-funciona)
- [4. Tamaños de Clave](#4-tamaños-de-clave)
- [5. Modos de Operación](#5-modos-de-operación)
  - [5.1 ECB (Electronic Codebook)](#51-ecb-electronic-codebook)
  - [5.2 CBC (Cipher Block Chaining)](#52-cbc-cipher-block-chaining)
  - [5.3 CTR (Counter)](#53-ctr-counter)
  - [5.4 GCM (Galois/Counter Mode)](#54-gcm-galoiscounter-mode)
  - [5.5 CFB (Cipher Feedback)](#55-cfb-cipher-feedback)
  - [5.6 OFB (Output Feedback)](#56-ofb-output-feedback)
  - [5.7 CCM (Counter with CBC-MAC)](#57-ccm-counter-with-cbc-mac)
- [6. Comparación de los Modos de Operación](#6-comparación-de-los-modos-de-operación)
- [7. Padding (Relleno)](#7-padding-relleno)
  - [7.1 PKCS#7](#71-pkcs7)
  - [7.2 ISO 7816-4](#72-iso-7816-4)
  - [7.3 Zero Padding](#73-zero-padding)
  - [7.4 Sin Padding (No Padding)](#74-sin-padding-no-padding)
- [8. Consideraciones de Seguridad](#8-consideraciones-de-seguridad)
- [9. Referencias](#9-referencias)

---

## 1. ¿Qué es AES?

El AES (*Advanced Encryption Standard*) es el algoritmo de criptografía simétrica más utilizado en el mundo. Es un estándar del gobierno de los Estados Unidos, oficialmente publicado como **FIPS 197** por el NIST, y es adoptado globalmente en prácticamente todos los protocolos y sistemas de seguridad modernos — incluyendo TLS 1.3, SSH, IPsec, Wi-Fi WPA2, cifrado de disco (BitLocker, FileVault, LUKS) y muchos otros.

El AES es un **cifrado por bloques** (*block cipher*): opera sobre bloques de datos de tamaño fijo de **128 bits (16 bytes)**, usando claves de **128**, **192** o **256 bits**. Fue diseñado para ser eficiente tanto en software como en hardware, y permanece seguro contra todos los ataques prácticos conocidos.

---

## 2. Historia

En la década de 1990, el **DES** (*Data Encryption Standard*), que había sido el estándar desde 1977, estaba claramente envejeciendo. Con una clave de solo 56 bits, ya podía ser roto por fuerza bruta — en 1999, una máquina dedicada rompió el DES en menos de 24 horas.

En **enero de 1997**, el NIST (*National Institute of Standards and Technology*) lanzó una convocatoria pública internacional para proponer un nuevo estándar de cifrado. El proceso fue abierto y transparente:

- **15 algoritmos** fueron presentados por equipos de todo el mundo.
- **5 finalistas** fueron seleccionados: Rijndael, Serpent, Twofish, RC6 y MARS.
- En **octubre de 2000**, el NIST anunció al ganador: **Rijndael**.

El Rijndael fue desarrollado por dos criptógrafos belgas, **Joan Daemen** y **Vincent Rijmen**, del laboratorio ESAT/COSIC de la Universidad KU Leuven, en Bélgica. La elección sorprendió a muchos observadores, que no esperaban que el gobierno estadounidense adoptara un estándar creado por no estadounidenses — lo que demostró la seriedad e imparcialidad del proceso de selección.

El **26 de noviembre de 2001**, el AES fue oficialmente publicado como **FIPS 197** por el NIST.

---

## 3. Cómo Funciona

El AES es un **cifrado por bloques** (*block cipher*): opera sobre bloques de datos de tamaño fijo de **128 bits (16 bytes)**. Si los datos a cifrar son mayores que 128 bits, se necesita un **modo de operación** (sección 5) para procesar múltiples bloques.

Internamente, el AES utiliza una **red de sustitución-permutación** (*substitution-permutation network* — SPN). Los datos pasan por múltiples rondas (*rounds*) de transformación, donde cada ronda aplica cuatro operaciones:

1. **SubBytes** — Cada byte del bloque es sustituido por otro usando una tabla de sustitución (S-box). Esta etapa introduce **no linealidad**, esencial para la seguridad.

2. **ShiftRows** — Las filas de la matriz de estado (4×4 bytes) son desplazadas cíclicamente. La primera fila no cambia, la segunda se desplaza 1 posición, la tercera 2 posiciones y la cuarta 3 posiciones. Esto garantiza la **difusión** entre las columnas.

3. **MixColumns** — Cada columna de la matriz es transformada por una multiplicación de matrices en el campo GF(2⁸). Esto proporciona **difusión** adicional, haciendo que cada byte de salida dependa de todos los bytes de la columna de entrada. (Esta etapa se omite en la última ronda.)

4. **AddRoundKey** — El bloque se combina (XOR) con una subclave derivada de la clave principal. Sin esta etapa, las operaciones anteriores serían solo una sustitución fija que podría ser precalculada.

---

## 4. Tamaños de Clave

El AES soporta tres tamaños de clave. La diferencia principal es el número de rondas de transformación:

| Tamaño de Clave | Número de Rondas | Nivel de Seguridad |
|---|---|---|
| 128 bits (16 bytes) | 10 | Seguro para uso general |
| 192 bits (24 bytes) | 12 | Margen de seguridad adicional |
| 256 bits (32 bytes) | 14 | Máximo — requerido para datos clasificados por el gobierno de EE.UU. |

Los tres tamaños se consideran seguros actualmente. El **AES-128** es suficiente para la gran mayoría de casos de uso. El **AES-256** se recomienda cuando se desea un margen de seguridad extra contra posibles avances futuros (incluyendo la computación cuántica, donde el algoritmo de Grover reduciría efectivamente la seguridad del AES-256 a ~128 bits simétricos).

---

## 5. Modos de Operación

Como el AES opera en bloques de 128 bits, se necesita un **modo de operación** para cifrar datos mayores que un solo bloque. Cada modo define cómo los bloques son procesados y encadenados, y cada uno tiene propiedades de seguridad y rendimiento distintas.

### 5.1 ECB (Electronic Codebook)

**Referencia**: NIST SP 800-38A

Cada bloque se cifra **independientemente** con la misma clave. No utiliza IV (*Initialization Vector*).

```
Bloque 1 → AES(clave) → Bloque cifrado 1
Bloque 2 → AES(clave) → Bloque cifrado 2
Bloque 3 → AES(clave) → Bloque cifrado 3
```

**INSEGURO para la mayoría de usos.** El principal problema es que bloques de texto claro idénticos producen bloques cifrados idénticos, lo que filtra patrones de los datos originales. El ejemplo clásico es el "pingüino ECB": al cifrar una imagen con ECB, la silueta de la imagen original permanece claramente visible en el resultado cifrado.

El ECB solo es aceptable en escenarios muy específicos, como cifrar un solo bloque de datos (por ejemplo, una única clave AES).

### 5.2 CBC (Cipher Block Chaining)

**Referencia**: NIST SP 800-38A

Cada bloque de texto claro se combina (XOR) con el **bloque cifrado anterior** antes de ser cifrado. El primer bloque usa un **IV** (*Initialization Vector*) de 16 bytes.

```
Bloque cifrado 1 = AES(clave, IV ⊕ Bloque 1)
Bloque cifrado 2 = AES(clave, Bloque cifrado 1 ⊕ Bloque 2)
Bloque cifrado 3 = AES(clave, Bloque cifrado 2 ⊕ Bloque 3)
```

**Características:**

- El IV debe ser **aleatorio e impredecible** para cada operación de cifrado.
- El cifrado es **secuencial** (no puede ser paralelizado).
- El descifrado **puede** ser paralelizado.
- Requiere **padding** (ya que los datos deben ser múltiplo del tamaño del bloque).
- Vulnerable a **ataques de padding oracle** si no se combina con autenticación (MAC).

### 5.3 CTR (Counter)

**Referencia**: NIST SP 800-38A

Transforma el cifrado por bloques en un **cifrado de flujo** (*stream cipher*). Un **nonce** concatenado con un **contador** secuencial se cifra, y el resultado se combina (XOR) con el texto claro.

```
Keystream 1 = AES(clave, nonce || contador_1)    →  Cifrado 1 = Keystream 1 ⊕ Bloque 1
Keystream 2 = AES(clave, nonce || contador_2)    →  Cifrado 2 = Keystream 2 ⊕ Bloque 2
```

**Características:**

- Totalmente **paralelizable** (tanto cifrado como descifrado).
- **No requiere padding** — opera byte a byte.
- El **nonce nunca debe ser reutilizado** con la misma clave. La reutilización compromete completamente la seguridad.
- No proporciona autenticación — solo confidencialidad.

### 5.4 GCM (Galois/Counter Mode)

**Referencia**: NIST SP 800-38D (2007)

El GCM combina el modo **CTR** (para confidencialidad) con la autenticación **GHASH** (basada en multiplicación en el campo de Galois). Es un modo **AEAD** (*Authenticated Encryption with Associated Data*), lo que significa que proporciona **confidencialidad y autenticidad** simultáneamente.

**Características:**

- Produce una **etiqueta de autenticación** (típicamente 128 bits) que permite verificar si los datos han sido adulterados.
- Soporta **AAD** (*Additional Authenticated Data*): datos que son autenticados pero no cifrados (como encabezados de protocolo).
- El nonce/IV recomendado es de **96 bits (12 bytes)** — longitudes diferentes son soportadas pero reducen la seguridad.
- Totalmente **paralelizable**.
- El **nonce nunca debe ser reutilizado** con la misma clave. La reutilización en GCM es catastrófica: permite recuperar la clave de autenticación y falsificar mensajes.

El GCM es el **modo recomendado para la mayoría de las aplicaciones** modernas. Se usa en TLS 1.3, SSH, IPsec y muchos otros protocolos.

### 5.5 CFB (Cipher Feedback)

**Referencia**: NIST SP 800-38A

Transforma el cifrado por bloques en un **cifrado de flujo auto-sincronizante**. El bloque cifrado anterior (o el IV, en el caso del primer bloque) se cifra, y el resultado se combina (XOR) con el texto claro.

```
Keystream 1 = AES(clave, IV)                →  Cifrado 1 = Keystream 1 ⊕ Bloque 1
Keystream 2 = AES(clave, Cifrado 1)         →  Cifrado 2 = Keystream 2 ⊕ Bloque 2
```

**Características:**

- El cifrado es **secuencial**.
- El descifrado **puede** ser paralelizado.
- Requiere un **IV** de 16 bytes.
- No requiere padding.
- Los errores de bit en el texto cifrado afectan al bloque actual y al siguiente, luego se autocorrigen.

### 5.6 OFB (Output Feedback)

**Referencia**: NIST SP 800-38A

Genera un **keystream independiente** del texto claro y del texto cifrado. El resultado del cifrado del IV (o del keystream anterior) se usa como entrada para el siguiente paso, y el keystream se combina (XOR) con el texto claro.

```
Keystream 1 = AES(clave, IV)              →  Cifrado 1 = Keystream 1 ⊕ Bloque 1
Keystream 2 = AES(clave, Keystream 1)     →  Cifrado 2 = Keystream 2 ⊕ Bloque 2
```

**Características:**

- Cifrado y descifrado son **idénticos** (misma operación XOR).
- **No paralelizable** (ni cifrado ni descifrado).
- **Los errores de bit no se propagan** — un bit corrompido en el texto cifrado afecta solo al bit correspondiente en el texto claro.
- El **IV nunca debe ser reutilizado** con la misma clave.
- No requiere padding.

### 5.7 CCM (Counter with CBC-MAC)

**Referencia**: NIST SP 800-38C, RFC 3610

El CCM combina el modo **CTR** (para confidencialidad) con **CBC-MAC** (para autenticación). Al igual que el GCM, es un modo **AEAD**.

**Características:**

- Requiere **dos pasadas** sobre los datos (una para el MAC, otra para el cifrado), a diferencia del GCM que lo hace en una sola pasada.
- El nonce tiene un tamaño entre **7 y 13 bytes** (por defecto: 11 bytes). Existe una relación inversa: L + N = 15, donde L es el campo que define el tamaño máximo del mensaje y N es el tamaño del nonce.
- Soporta AAD.
- Ampliamente usado en **IEEE 802.11i (Wi-Fi WPA2)** y **Bluetooth**.
- Menos eficiente que el GCM, pero puede ser preferido en entornos con restricciones de hardware.

---

## 6. Comparación de los Modos de Operación

| Modo | Confidencialidad | Autenticación | Paralelizable (Cifrar) | Paralelizable (Descifrar) | IV/Nonce | Padding |
|---|---|---|---|---|---|---|
| ECB | Sí | No | Sí | Sí | No usa | Sí |
| CBC | Sí | No | No | Sí | 16 bytes (aleatorio) | Sí |
| CTR | Sí | No | Sí | Sí | Nonce (único) | No |
| **GCM** | **Sí** | **Sí** | **Sí** | **Sí** | **12 bytes (recomendado)** | **No** |
| CFB | Sí | No | No | Sí | 16 bytes | No |
| OFB | Sí | No | No | No | 16 bytes (único) | No |
| **CCM** | **Sí** | **Sí** | **Sí** | **Sí** | **7-13 bytes** | **No** |

> **Recomendación**: para la mayoría de los escenarios, usa **GCM**. Proporciona confidencialidad y autenticación, es paralelizable y es el modo estándar en los protocolos modernos. Usa **CCM** cuando trabajes con hardware restringido o protocolos que lo requieran (como WPA2).

---

## 7. Padding (Relleno)

El padding es necesario solo para **modos de bloque** (ECB y CBC), donde el texto claro debe ser un múltiplo exacto de 16 bytes (128 bits). Los modos de flujo (CTR, CFB, OFB) y los modos autenticados (GCM, CCM) no necesitan padding.

### 7.1 PKCS#7

**Referencia**: RFC 5652

El esquema de padding más utilizado y recomendado. Rellena con N bytes, cada uno con el valor N (donde N es la cantidad de bytes necesarios para completar el bloque).

```
Datos:    [0x48 0x65 0x6C 0x6C 0x6F]              (5 bytes — "Hello")
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B]
                                                    (11 bytes de padding, cada uno = 0x0B)
```

Si los datos ya son múltiplo de 16, se agrega un **bloque completo de padding** (16 bytes con valor 0x10). Esto garantiza que el padding es siempre **inequívocamente reversible**.

### 7.2 ISO 7816-4

**Referencia**: ISO/IEC 7816-4

También llamado *bit padding*. Rellena con el byte `0x80` seguido de bytes `0x00` hasta completar el bloque.

```
Datos:    [0x48 0x65 0x6C 0x6C 0x6F]
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x80 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
```

Originalmente usado en aplicaciones de **tarjetas inteligentes**. También es inequívocamente reversible, ya que el marcador `0x80` indica dónde comienza el padding.

### 7.3 Zero Padding

Rellena con bytes `0x00` hasta completar el bloque.

```
Datos:    [0x48 0x65 0x6C 0x6C 0x6F]
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
```

**Problema**: si el texto claro termina con bytes `0x00`, es imposible distinguir los bytes reales de los bytes de padding. Esto hace que el zero padding sea **ambiguo para datos binarios** y no recomendado para uso general. Puede ser aceptable cuando se sabe que los datos son exclusivamente texto.

### 7.4 Sin Padding (No Padding)

No se agrega ningún relleno. El texto claro **debe** tener un tamaño exacto múltiplo de 16 bytes. De lo contrario, la operación fallará.

Se usa con modos de flujo (CTR, CFB, OFB) y modos autenticados (GCM, CCM), que operan a nivel de byte y no requieren alineación de bloque.

### Comparación de los Esquemas de Padding

| Esquema | Reversible sin Ambigüedad | Cuándo Usar |
|---|---|---|
| PKCS#7 | Sí | **Recomendado** para ECB y CBC |
| ISO 7816-4 | Sí | Tarjetas inteligentes o cuando lo exige un estándar |
| Zero Padding | No (datos binarios) | Solo texto — uso heredado |
| Sin Padding | N/A | CTR, GCM, CFB, OFB, CCM |

---

## 8. Consideraciones de Seguridad

- **Nunca reutilices el nonce/IV con la misma clave.** En CTR y GCM, la reutilización es catastrófica. En CBC, compromete la confidencialidad de los bloques iniciales.
- **Siempre prefiere modos autenticados** (GCM o CCM). Sin autenticación, un atacante puede alterar el texto cifrado de formas que producen cambios predecibles en el texto claro.
- **Nunca uses ECB** para datos mayores que un bloque, ya que filtra patrones.
- **Derivación de claves**: nunca uses una contraseña directamente como clave AES. Usa funciones de derivación de claves como PBKDF2, HKDF o Argon2 para transformar una contraseña en una clave criptográfica adecuada.
- **Generación de IV/nonce**: usa siempre un generador de números aleatorios criptográficamente seguro (CSPRNG).

---

## 9. Referencias

### Estándares NIST (FIPS)

- [**FIPS 197**](https://csrc.nist.gov/pubs/fips/197/final) — Advanced Encryption Standard (AES). NIST, 2001 (actualizado 2023).

### Publicaciones Especiales NIST (SP)

- [**NIST SP 800-38A**](https://csrc.nist.gov/pubs/sp/800/38/a/final) — Recommendation for Block Cipher Modes of Operation: Methods and Techniques (ECB, CBC, CFB, OFB, CTR). NIST, 2001.
- [**NIST SP 800-38C**](https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final) — Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality. NIST, 2004.
- [**NIST SP 800-38D**](https://csrc.nist.gov/pubs/sp/800/38/d/final) — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC. NIST, 2007.

### RFCs (IETF)

- [**RFC 5652**](https://datatracker.ietf.org/doc/html/rfc5652) — Cryptographic Message Syntax (CMS). IETF, 2009.
- [**RFC 3610**](https://datatracker.ietf.org/doc/html/rfc3610) — Counter with CBC-MAC (CCM). IETF, 2003.
