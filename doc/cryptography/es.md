# Criptografía

Una guía completa sobre criptografía, abarcando desde conceptos fundamentales hasta detalles técnicos de los principales algoritmos criptográficos.

## Índice

- [1. ¿Qué es la Criptografía?](#1-qué-es-la-criptografía)
- [2. Criptografía Simétrica vs Asimétrica](#2-criptografía-simétrica-vs-asimétrica)
- [3. Funciones Hash](#3-funciones-hash)
- [4. AES (Advanced Encryption Standard)](#4-aes-advanced-encryption-standard)
- [5. RSA (Rivest-Shamir-Adleman)](#5-rsa-rivest-shamir-adleman)
- [6. Cuándo Usar AES vs RSA](#6-cuándo-usar-aes-vs-rsa)
- [7. Referencias](#7-referencias)

---

## 1. ¿Qué es la Criptografía?

### 1.1 Definición

La palabra **criptografía** proviene del griego: *kryptós* (oculto, secreto) y *gráphein* (escritura). En términos simples, la criptografía es la ciencia de transformar información legible en algo incomprensible, de modo que solo quien posea la "clave" correcta pueda revertir el proceso y leer la información original.

Piensa en una caja fuerte: cualquier persona puede ver la caja fuerte, pero solo quien tiene la llave (o la combinación) puede abrirla y acceder a lo que hay dentro. La criptografía funciona de la misma manera: "bloquea" tus datos para que solo los destinatarios autorizados puedan "desbloquearlos" y leerlos.

### 1.2 ¿Por qué es Importante la Criptografía?

La criptografía sustenta cuatro pilares fundamentales de la seguridad de la información:

- **Confidencialidad**: garantiza que solo las personas autorizadas puedan leer los datos. Ejemplo: cuando accedes a tu banco desde el celular, la criptografía impide que alguien intercepte tu información financiera.
- **Integridad**: garantiza que los datos no han sido alterados durante el tránsito. Si alguien modifica un mensaje cifrado, el destinatario puede detectar la adulteración.
- **Autenticación**: confirma la identidad de quien envió los datos. Los certificados digitales, por ejemplo, usan criptografía para demostrar que un sitio web es realmente quien dice ser.
- **No repudio**: impide que el autor niegue haber enviado un mensaje. Las firmas digitales proporcionan prueba matemática de autoría.

En el día a día, la criptografía está presente en prácticamente todo:

- **HTTPS**: el candado en el navegador indica que la comunicación con el sitio web está cifrada.
- **Mensajería**: aplicaciones como WhatsApp y Signal usan cifrado de extremo a extremo.
- **Banca en línea**: todas las transacciones están protegidas por múltiples capas criptográficas.
- **Wi-Fi**: el protocolo WPA2/WPA3 cifra el tráfico de tu red inalámbrica.

### 1.3 Conceptos Fundamentales

Antes de avanzar, es importante entender algunos términos que se usarán a lo largo de este documento:

- **Texto claro** (*plaintext*): la información original, legible. Ejemplo: el mensaje "¡Hola, mundo!".
- **Texto cifrado** (*ciphertext*): el resultado de la criptografía — datos desordenados e ilegibles. Ejemplo: `a7f3b2c9e1d8...`.
- **Clave** (*key*): un valor secreto utilizado para cifrar y/o descifrar los datos. Cuanto mayor sea la clave, más difícil es romper la criptografía.
- **Cifrar** (*encrypt*): el proceso de transformar texto claro en texto cifrado usando un algoritmo y una clave.
- **Descifrar** (*decrypt*): el proceso inverso — transformar texto cifrado de vuelta en texto claro usando la clave correcta.
- **Algoritmo**: el procedimiento matemático que define cómo los datos son cifrados y descifrados. Ejemplos: AES, RSA.

---

## 2. Criptografía Simétrica vs Asimétrica

Existen dos grandes categorías de criptografía. Entender la diferencia entre ellas es fundamental para saber cuándo y cómo usar cada una.

### 2.1 Criptografía Simétrica

En la criptografía simétrica, **la misma clave** se usa tanto para cifrar como para descifrar los datos.

Analogía: imagina una puerta con una cerradura común. La misma llave que cierra también abre. Si quieres que otra persona abra la puerta, necesitas entregarle una copia de la llave.

**Ventajas:**

- Extremadamente rápida — ideal para grandes volúmenes de datos.
- Algoritmos eficientes que pueden ser acelerados por hardware.

**Desventaja principal:**

- El **problema de la distribución de claves**: ¿cómo entregar la clave con seguridad al destinatario? Si alguien intercepta la clave durante el intercambio, toda la comunicación queda comprometida.

El algoritmo simétrico más utilizado actualmente es el **AES** (detallado en la sección 4).

### 2.2 Criptografía Asimétrica

En la criptografía asimétrica, se usan **dos claves matemáticamente relacionadas**: una **clave pública** y una **clave privada**.

- La **clave pública** puede ser compartida libremente con cualquier persona.
- La **clave privada** debe mantenerse en secreto absoluto.

Lo que una clave cifra, solo la otra puede descifrar.

Analogía: imagina un buzón de correo público. Cualquier persona puede depositar una carta por la ranura (cifrar con la clave pública), pero solo el dueño del buzón, que posee la llave de la cerradura, puede abrirlo y leer las cartas (descifrar con la clave privada).

**Ventajas:**

- Resuelve el problema de la distribución de claves — la clave pública puede ser enviada abiertamente.
- Permite firmas digitales y certificados.

**Desventajas:**

- Significativamente más lenta que la criptografía simétrica.
- El tamaño de los datos que pueden ser cifrados está limitado por el tamaño de la clave.

El algoritmo asimétrico más utilizado es el **RSA** (detallado en la sección 5).

### 2.3 Comparación Directa

| Característica | Simétrica | Asimétrica |
|---|---|---|
| Número de claves | 1 (compartida) | 2 (pública + privada) |
| Velocidad | Rápida | Lenta |
| Tamaño de los datos | Ilimitado | Limitado por el tamaño de la clave |
| Distribución de clave | Problemática (requiere canal seguro) | Simplificada (la clave pública es abierta) |
| Uso típico | Cifrar datos en masa | Intercambio de claves, firmas digitales |
| Ejemplo de algoritmo | AES | RSA |

### 2.4 Criptografía Híbrida

En la práctica, ambos tipos se usan **juntos** en un modelo llamado **criptografía híbrida**. Este es el modelo usado por prácticamente todos los protocolos modernos de seguridad (TLS/HTTPS, PGP, S/MIME).

El funcionamiento es:

1. Se genera una **clave simétrica aleatoria** (llamada clave de sesión).
2. Los **datos se cifran** con esta clave simétrica (rápido, sin límite de tamaño).
3. La **clave simétrica se cifra** con la clave pública RSA del destinatario (resuelve la distribución).
4. El destinatario usa su **clave privada RSA** para descifrar la clave simétrica.
5. Con la clave simétrica recuperada, el destinatario **descifra los datos**.

De esta forma, se obtiene lo mejor de ambos mundos: la velocidad de la criptografía simétrica y la seguridad en el intercambio de claves de la criptografía asimétrica.

---

## 3. Funciones Hash

Las funciones hash se usan frecuentemente en conjunto con algoritmos de criptografía (por ejemplo, en el padding OAEP del RSA y en la autenticación del GCM en AES). Por eso, es importante entenderlas antes de profundizar en los detalles del AES y RSA.

### 3.1 ¿Qué es una Función Hash?

Una **función hash criptográfica** es una función matemática que recibe una entrada de cualquier tamaño y produce una salida de tamaño fijo, llamada **digest** o **hash**. La operación es **unidireccional**: es computacionalmente inviable recuperar la entrada original a partir del hash.

Analogía: piensa en una huella dactilar. Cada persona tiene una huella dactilar única que la identifica, pero mirando la huella dactilar, no puedes reconstruir a la persona entera. De la misma forma, el hash es una "huella dactilar" de los datos.

### 3.2 Propiedades Esenciales

Una buena función hash criptográfica debe poseer:

- **Determinismo**: la misma entrada siempre produce el mismo hash.
- **Efecto avalancha**: un cambio mínimo en la entrada (incluso un único bit) genera un hash completamente diferente.
- **Resistencia a la preimagen**: dado un hash, es inviable encontrar una entrada que produzca ese hash.
- **Resistencia a la segunda preimagen**: dada una entrada, es inviable encontrar otra entrada diferente que produzca el mismo hash.
- **Resistencia a colisiones**: es inviable encontrar dos entradas distintas que produzcan el mismo hash.

### 3.3 Algoritmos de Hash

#### SHA-1 (Secure Hash Algorithm 1)

| Propiedad | Valor |
|---|---|
| Tamaño de salida | 160 bits (20 bytes) |
| Tamaño del bloque interno | 512 bits |
| Estado | **DESCONTINUADO** |

El SHA-1 fue ampliamente usado durante décadas, pero en 2017, investigadores de Google y CWI Amsterdam demostraron la primera colisión práctica (ataque SHAttered), probando que dos entradas diferentes podían producir el mismo hash SHA-1. Desde entonces, SHA-1 se considera **inseguro** y no debe usarse en nuevos sistemas. Todavía se encuentra en sistemas heredados por razones de compatibilidad.

#### SHA-2 (Familia)

La familia SHA-2, estandarizada por el NIST en FIPS 180-4, es el estándar actual y ampliamente utilizado:

| Variante | Tamaño de Salida | Tamaño del Bloque Interno | Uso Común |
|---|---|---|---|
| SHA-224 | 224 bits (28 bytes) | 512 bits | Poco usado, compatibilidad |
| SHA-256 | 256 bits (32 bytes) | 512 bits | **Estándar recomendado** para uso general |
| SHA-384 | 384 bits (48 bytes) | 1024 bits | Alta seguridad |
| SHA-512 | 512 bits (64 bytes) | 1024 bits | Alta seguridad, eficiente en 64 bits |

El **SHA-256** es la opción más común y recomendada para la mayoría de los escenarios, ofreciendo un buen equilibrio entre seguridad y rendimiento.

#### SHA-3 (Familia)

El SHA-3 fue estandarizado por el NIST en 2015 (FIPS 202) y está basado en el algoritmo **Keccak**, que utiliza una construcción interna completamente diferente al SHA-2 (llamada *sponge construction*). **No es un reemplazo** del SHA-2 (que sigue siendo seguro), sino una **alternativa** con una arquitectura distinta, ofreciendo diversidad criptográfica.

| Variante | Tamaño de Salida | Tamaño del Bloque Interno (rate) |
|---|---|---|
| SHA3-256 | 256 bits (32 bytes) | 1088 bits |
| SHA3-512 | 512 bits (64 bytes) | 576 bits |

### 3.4 Aplicaciones de las Funciones Hash

- **Verificación de integridad**: verificar si un archivo fue corrompido o adulterado durante la descarga.
- **Almacenamiento de contraseñas**: se almacena el hash de la contraseña, no la contraseña en sí. (En la práctica, se usan funciones especializadas como Argon2, bcrypt o PBKDF2, que agregan *salt* y son deliberadamente lentas.)
- **Firmas digitales**: el documento es primero "hasheado" y luego el hash es firmado con la clave privada (*hash-then-sign*).
- **HMAC**: *Hash-based Message Authentication Code* — combina una clave secreta con el hash para verificar autenticidad e integridad simultáneamente.
- **Padding OAEP**: el esquema de padding OAEP del RSA usa funciones hash internamente (detallado en la sección 5.4).

---

## 4. AES (Advanced Encryption Standard)

El AES es el algoritmo de criptografía simétrica más utilizado en el mundo. Es un estándar del gobierno de los Estados Unidos y es adoptado globalmente en prácticamente todos los protocolos y sistemas de seguridad modernos.

### 4.1 Historia

En la década de 1990, el **DES** (*Data Encryption Standard*), que había sido el estándar desde 1977, estaba claramente envejeciendo. Con una clave de solo 56 bits, ya podía ser roto por fuerza bruta — en 1999, una máquina dedicada rompió el DES en menos de 24 horas.

En **enero de 1997**, el NIST (*National Institute of Standards and Technology*) lanzó una convocatoria pública internacional para proponer un nuevo estándar de cifrado. El proceso fue abierto y transparente:

- **15 algoritmos** fueron presentados por equipos de todo el mundo.
- **5 finalistas** fueron seleccionados: Rijndael, Serpent, Twofish, RC6 y MARS.
- En **octubre de 2000**, el NIST anunció al ganador: **Rijndael**.

El Rijndael fue desarrollado por dos criptógrafos belgas, **Joan Daemen** y **Vincent Rijmen**, del laboratorio ESAT/COSIC de la Universidad KU Leuven, en Bélgica. La elección sorprendió a muchos observadores, que no esperaban que el gobierno estadounidense adoptara un estándar creado por no estadounidenses — lo que demostró la seriedad e imparcialidad del proceso de selección.

El **26 de noviembre de 2001**, el AES fue oficialmente publicado como **FIPS 197** por el NIST.

### 4.2 Cómo Funciona

El AES es un **cifrado por bloques** (*block cipher*): opera sobre bloques de datos de tamaño fijo de **128 bits (16 bytes)**. Si los datos a cifrar son mayores que 128 bits, se necesita un **modo de operación** (sección 4.4) para procesar múltiples bloques.

Internamente, el AES utiliza una **red de sustitución-permutación** (*substitution-permutation network* — SPN). Los datos pasan por múltiples rondas (*rounds*) de transformación, donde cada ronda aplica cuatro operaciones:

1. **SubBytes** — Cada byte del bloque es sustituido por otro usando una tabla de sustitución (S-box). Esta etapa introduce **no linealidad**, esencial para la seguridad.

2. **ShiftRows** — Las filas de la matriz de estado (4×4 bytes) son desplazadas cíclicamente. La primera fila no cambia, la segunda se desplaza 1 posición, la tercera 2 posiciones y la cuarta 3 posiciones. Esto garantiza la **difusión** entre las columnas.

3. **MixColumns** — Cada columna de la matriz es transformada por una multiplicación de matrices en el campo GF(2⁸). Esto proporciona **difusión** adicional, haciendo que cada byte de salida dependa de todos los bytes de la columna de entrada. (Esta etapa se omite en la última ronda.)

4. **AddRoundKey** — El bloque se combina (XOR) con una subclave derivada de la clave principal. Sin esta etapa, las operaciones anteriores serían solo una sustitución fija que podría ser precalculada.

### 4.3 Tamaños de Clave

El AES soporta tres tamaños de clave. La diferencia principal es el número de rondas de transformación:

| Tamaño de Clave | Número de Rondas | Nivel de Seguridad |
|---|---|---|
| 128 bits (16 bytes) | 10 | Seguro para uso general |
| 192 bits (24 bytes) | 12 | Margen de seguridad adicional |
| 256 bits (32 bytes) | 14 | Máximo — requerido para datos clasificados por el gobierno de EE.UU. |

Los tres tamaños se consideran seguros actualmente. El **AES-128** es suficiente para la gran mayoría de casos de uso. El **AES-256** se recomienda cuando se desea un margen de seguridad extra contra posibles avances futuros (incluyendo la computación cuántica, donde el algoritmo de Grover reduciría efectivamente la seguridad del AES-256 a ~128 bits simétricos).

### 4.4 Modos de Operación

Como el AES opera en bloques de 128 bits, se necesita un **modo de operación** para cifrar datos mayores que un solo bloque. Cada modo define cómo los bloques son procesados y encadenados, y cada uno tiene propiedades de seguridad y rendimiento distintas.

#### 4.4.1 ECB (Electronic Codebook)

**Referencia**: NIST SP 800-38A

Cada bloque se cifra **independientemente** con la misma clave. No utiliza IV (*Initialization Vector*).

```
Bloque 1 → AES(clave) → Bloque cifrado 1
Bloque 2 → AES(clave) → Bloque cifrado 2
Bloque 3 → AES(clave) → Bloque cifrado 3
```

**INSEGURO para la mayoría de usos.** El principal problema es que bloques de texto claro idénticos producen bloques cifrados idénticos, lo que filtra patrones de los datos originales. El ejemplo clásico es el "pingüino ECB": al cifrar una imagen con ECB, la silueta de la imagen original permanece claramente visible en el resultado cifrado.

El ECB solo es aceptable en escenarios muy específicos, como cifrar un solo bloque de datos (por ejemplo, una única clave AES).

#### 4.4.2 CBC (Cipher Block Chaining)

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

#### 4.4.3 CTR (Counter)

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

#### 4.4.4 GCM (Galois/Counter Mode)

**Referencia**: NIST SP 800-38D (2007)

El GCM combina el modo **CTR** (para confidencialidad) con la autenticación **GHASH** (basada en multiplicación en el campo de Galois). Es un modo **AEAD** (*Authenticated Encryption with Associated Data*), lo que significa que proporciona **confidencialidad y autenticidad** simultáneamente.

**Características:**

- Produce una **etiqueta de autenticación** (típicamente 128 bits) que permite verificar si los datos han sido adulterados.
- Soporta **AAD** (*Additional Authenticated Data*): datos que son autenticados pero no cifrados (como encabezados de protocolo).
- El nonce/IV recomendado es de **96 bits (12 bytes)** — longitudes diferentes son soportadas pero reducen la seguridad.
- Totalmente **paralelizable**.
- El **nonce nunca debe ser reutilizado** con la misma clave. La reutilización en GCM es catastrófica: permite recuperar la clave de autenticación y falsificar mensajes.

El GCM es el **modo recomendado para la mayoría de las aplicaciones** modernas. Se usa en TLS 1.3, SSH, IPsec y muchos otros protocolos.

#### 4.4.5 CFB (Cipher Feedback)

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

#### 4.4.6 OFB (Output Feedback)

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

#### 4.4.7 CCM (Counter with CBC-MAC)

**Referencia**: NIST SP 800-38C, RFC 3610

El CCM combina el modo **CTR** (para confidencialidad) con **CBC-MAC** (para autenticación). Al igual que el GCM, es un modo **AEAD**.

**Características:**

- Requiere **dos pasadas** sobre los datos (una para el MAC, otra para el cifrado), a diferencia del GCM que lo hace en una sola pasada.
- El nonce tiene un tamaño entre **7 y 13 bytes** (por defecto: 11 bytes). Existe una relación inversa: L + N = 15, donde L es el campo que define el tamaño máximo del mensaje y N es el tamaño del nonce.
- Soporta AAD.
- Ampliamente usado en **IEEE 802.11i (Wi-Fi WPA2)** y **Bluetooth**.
- Menos eficiente que el GCM, pero puede ser preferido en entornos con restricciones de hardware.

### 4.5 Comparación de los Modos de Operación

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

### 4.6 Padding (Relleno)

El padding es necesario solo para **modos de bloque** (ECB y CBC), donde el texto claro debe ser un múltiplo exacto de 16 bytes (128 bits). Los modos de flujo (CTR, CFB, OFB) y los modos autenticados (GCM, CCM) no necesitan padding.

#### 4.6.1 PKCS#7

**Referencia**: RFC 5652

El esquema de padding más utilizado y recomendado. Rellena con N bytes, cada uno con el valor N (donde N es la cantidad de bytes necesarios para completar el bloque).

```
Datos:    [0x48 0x65 0x6C 0x6C 0x6F]              (5 bytes — "Hello")
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B]
                                                    (11 bytes de padding, cada uno = 0x0B)
```

Si los datos ya son múltiplo de 16, se agrega un **bloque completo de padding** (16 bytes con valor 0x10). Esto garantiza que el padding es siempre **inequívocamente reversible**.

#### 4.6.2 ISO 7816-4

**Referencia**: ISO/IEC 7816-4

También llamado *bit padding*. Rellena con el byte `0x80` seguido de bytes `0x00` hasta completar el bloque.

```
Datos:    [0x48 0x65 0x6C 0x6C 0x6F]
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x80 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
```

Originalmente usado en aplicaciones de **tarjetas inteligentes**. También es inequívocamente reversible, ya que el marcador `0x80` indica dónde comienza el padding.

#### 4.6.3 Zero Padding

Rellena con bytes `0x00` hasta completar el bloque.

```
Datos:    [0x48 0x65 0x6C 0x6C 0x6F]
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
```

**Problema**: si el texto claro termina con bytes `0x00`, es imposible distinguir los bytes reales de los bytes de padding. Esto hace que el zero padding sea **ambiguo para datos binarios** y no recomendado para uso general. Puede ser aceptable cuando se sabe que los datos son exclusivamente texto.

#### 4.6.4 Sin Padding (No Padding)

No se agrega ningún relleno. El texto claro **debe** tener un tamaño exacto múltiplo de 16 bytes. De lo contrario, la operación fallará.

Se usa con modos de flujo (CTR, CFB, OFB) y modos autenticados (GCM, CCM), que operan a nivel de byte y no requieren alineación de bloque.

#### Comparación de los Esquemas de Padding

| Esquema | Reversible sin Ambigüedad | Cuándo Usar |
|---|---|---|
| PKCS#7 | Sí | **Recomendado** para ECB y CBC |
| ISO 7816-4 | Sí | Tarjetas inteligentes o cuando lo exige un estándar |
| Zero Padding | No (datos binarios) | Solo texto — uso heredado |
| Sin Padding | N/A | CTR, GCM, CFB, OFB, CCM |

### 4.7 Consideraciones de Seguridad

- **Nunca reutilices el nonce/IV con la misma clave.** En CTR y GCM, la reutilización es catastrófica. En CBC, compromete la confidencialidad de los bloques iniciales.
- **Siempre prefiere modos autenticados** (GCM o CCM). Sin autenticación, un atacante puede alterar el texto cifrado de formas que producen cambios predecibles en el texto claro.
- **Nunca uses ECB** para datos mayores que un bloque, ya que filtra patrones.
- **Derivación de claves**: nunca uses una contraseña directamente como clave AES. Usa funciones de derivación de claves como PBKDF2, HKDF o Argon2 para transformar una contraseña en una clave criptográfica adecuada.
- **Generación de IV/nonce**: usa siempre un generador de números aleatorios criptográficamente seguro (CSPRNG).

---

## 5. RSA (Rivest-Shamir-Adleman)

El RSA es el algoritmo de criptografía asimétrica más conocido y utilizado. Puede usarse tanto para **cifrado** como para **firmas digitales**.

### 5.1 Historia

En **1977**, tres investigadores del MIT — **Ron Rivest**, **Adi Shamir** y **Leonard Adleman** — publicaron el primer criptosistema de clave pública práctico. Rivest y Shamir, ambos científicos de la computación, proponían funciones candidatas, mientras Adleman, matemático, intentaba romperlas. Después de 42 intentos fallidos, en abril de 1977, Rivest formalizó la idea que se convertiría en el RSA.

El algoritmo fue publicado en la revista **Scientific American** en 1977 y rápidamente se convirtió en el estándar para la criptografía de clave pública. La patente estadounidense del RSA expiró en **septiembre de 2000**, haciéndolo libre para su uso en todo el mundo.

El nombre "RSA" proviene de las iniciales de los apellidos de los tres creadores: **R**ivest, **S**hamir y **A**dleman.

### 5.2 Cómo Funciona

La seguridad del RSA se basa en un problema matemático: la **dificultad de factorizar el producto de dos números primos muy grandes**. Multiplicar dos primos es rápido, pero dado solo el resultado, encontrar los factores originales es computacionalmente inviable para números suficientemente grandes.

#### Generación de Claves

1. Se eligen dos números primos grandes **p** y **q** (cada uno con cientos de dígitos).
2. Se calcula **n = p × q** (el módulo). Este valor es público.
3. Se calcula **φ(n) = (p − 1) × (q − 1)** (la función totiente de Euler).
4. Se elige un exponente público **e**, coprimo a φ(n). El valor más utilizado es **e = 65537** (0x10001), elegido por ser primo y tener pocos bits activos (eficiente para la exponenciación).
5. Se calcula el exponente privado **d = e⁻¹ mod φ(n)** (el inverso modular de e).

- **Clave pública**: (n, e)
- **Clave privada**: (n, d)

#### Cifrado y Descifrado

- **Cifrar**: c = m^e mod n (donde m es el mensaje numérico y c es el texto cifrado)
- **Descifrar**: m = c^d mod n

La seguridad depende del hecho de que, sin conocer p y q (que componen d), es computacionalmente inviable calcular d a partir de solo (n, e).

### 5.3 Tamaños de Clave

El tamaño de la clave RSA (en bits) se refiere al tamaño del módulo **n**. Claves más grandes ofrecen más seguridad, pero son más lentas.

La tabla a continuación muestra la equivalencia entre el tamaño de la clave RSA y la seguridad equivalente en bits simétricos, según el **NIST SP 800-57 Part 1 Rev. 5**:

| Tamaño de Clave RSA | Seguridad Equivalente (bits simétricos) | Estado |
|---|---|---|
| 1024 bits | ~80 bits | **Obsoleto** — no usar |
| 2048 bits | ~112 bits | Mínimo recomendado actualmente |
| 3072 bits | ~128 bits | Buen margen de seguridad |
| 4096 bits | ~140 bits | Alta seguridad |
| 7680 bits | ~192 bits | Muy alta seguridad |
| 15360 bits | ~256 bits | Máxima seguridad (raro en la práctica) |

> **Recomendación**: usa al menos **2048 bits**. Para seguridad a largo plazo, prefiere **4096 bits**. Ten en cuenta que la generación de claves de 4096 bits puede ser significativamente más lenta.

El tamaño de la clave también limita el **tamaño máximo de los datos** que pueden ser cifrados directamente (detallado en la sección 5.4).

### 5.4 Esquemas de Padding

En RSA, el mensaje en texto claro necesita ser transformado en un número entre 0 y n−1 antes del cifrado. El **padding** (o esquema de codificación) es el proceso que realiza esta transformación de forma segura. Cifrar sin padding (llamado "textbook RSA") es extremadamente inseguro.

#### 5.4.1 PKCS#1 v1.5

**Referencia**: RFC 8017 (consolidación), originalmente RFC 2313

El esquema más antiguo y aún ampliamente encontrado. El formato del mensaje codificado es:

```
0x00 || 0x02 || PS || 0x00 || M
```

Donde:
- `PS` es un relleno de bytes **aleatorios no nulos** con un mínimo de 8 bytes.
- `M` es el mensaje original.

El tamaño máximo del mensaje es: **mLen ≤ k − 11** bytes (donde k es el tamaño de la clave en bytes).

**Vulnerabilidad**: en 1998, Daniel Bleichenbacher demostró un ataque (*Bleichenbacher's attack*, también llamado "million message attack") que explota servidores que revelan si el padding de un mensaje descifrado es válido o no. Este tipo de *padding oracle* permite que un atacante descifre mensajes sin la clave privada, enviando millones de textos cifrados modificados y observando las respuestas del servidor. Variantes de este ataque siguieron siendo explotables en 2018 (ROBOT) y 2023 (Marvin Attack).

**El PKCS#1 v1.5 se mantiene solo por compatibilidad con sistemas heredados. No debe usarse en nuevos proyectos.**

#### 5.4.2 OAEP (Optimal Asymmetric Encryption Padding)

El OAEP fue propuesto por **Bellare y Rogaway** en 1994 como una alternativa demostrablemente segura al PKCS#1 v1.5. Utiliza una estructura similar a una **red Feistel de dos rondas** combinada con funciones hash y una **MGF** (*Mask Generation Function*).

El proceso de codificación EME-OAEP (según RFC 8017) funciona así:

1. Se genera el hash de la **etiqueta** L (por defecto, una cadena vacía) para obtener `lHash`.
2. Se crea el bloque de datos: `DB = lHash || PS || 0x01 || M` (donde PS son bytes cero de relleno).
3. Se genera una **semilla aleatoria** de longitud igual al hash.
4. Se calcula `dbMask = MGF1(seed, longitud_de_DB)`.
5. Se calcula `maskedDB = DB ⊕ dbMask`.
6. Se calcula `seedMask = MGF1(maskedDB, longitud_del_hash)`.
7. Se calcula `maskedSeed = seed ⊕ seedMask`.
8. El mensaje codificado final es: `EM = 0x00 || maskedSeed || maskedDB`.

El tamaño máximo del mensaje es: **mLen ≤ k − 2·hLen − 2** bytes (donde hLen es el tamaño de la salida del hash en bytes).

#### Versiones de OAEP

| Versión | Referencia | Detalles |
|---|---|---|
| OAEP v1 | Bellare-Rogaway (1994) | Propuesta original con SHA-1 |
| OAEP v2.0 | PKCS#1 v2.0 (RFC 2437) | Incorporación al estándar PKCS#1 con MGF1 |
| OAEP v2.1 | PKCS#1 v2.1 (RFC 3447) / v2.2 (RFC 8017) | **Recomendado** — hash configurable, MGF1, soporte de etiqueta |

> **Recomendación**: usa siempre **OAEP v2.1** (o posterior) con **SHA-256** o superior. Según la RFC 8017: *"RSAES-OAEP is required to be supported for new applications"*.

### 5.5 Algoritmos de Hash Usados con RSA

Las funciones hash se usan en RSA en varios contextos:

- **Padding OAEP**: la función hash se usa para generar `lHash` y como base de la MGF1.
- **Firmas digitales**: el mensaje se hashea antes de ser firmado (*hash-then-sign*).
- **Huellas de claves**: identificación resumida de claves públicas.

La elección del hash afecta directamente al **tamaño máximo del mensaje** en OAEP (ya que `hLen` entra en la fórmula `k − 2·hLen − 2`).

| Algoritmo | Tamaño de Salida (hLen) | Estado con RSA | Mensaje Máximo (RSA-2048) |
|---|---|---|---|
| SHA-1 | 20 bytes | Heredado — evitar | 214 bytes |
| SHA-224 | 28 bytes | Válido, poco usado | 198 bytes |
| SHA-256 | 32 bytes | **Recomendado** (estándar) | 190 bytes |
| SHA-384 | 48 bytes | Alta seguridad | 158 bytes |
| SHA-512 | 64 bytes | Alta seguridad | 126 bytes |
| SHA3-256 | 32 bytes | Alternativa moderna | 190 bytes |
| SHA3-512 | 64 bytes | Alternativa moderna | 126 bytes |

> **Nota**: la columna "Mensaje Máximo" asume RSA-2048 (k = 256 bytes) y OAEP. Fórmula: k − 2·hLen − 2.

### 5.6 Formatos de Clave

Las claves RSA pueden almacenarse y transmitirse en diferentes formatos estandarizados. Cada formato tiene un propósito específico.

#### 5.6.1 PKCS#1

Formato **específico para RSA**. Contiene solo los parámetros matemáticos del RSA.

- **Clave pública**: contiene (n, e).
- **Clave privada**: contiene (n, e, d, p, q, dP, dQ, qInv).
- Codificación: ASN.1 DER, típicamente envuelta en PEM.

```
-----BEGIN RSA PUBLIC KEY-----
(datos codificados en Base64)
-----END RSA PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
(datos codificados en Base64)
-----END RSA PRIVATE KEY-----
```

#### 5.6.2 PKCS#8 (PrivateKeyInfo)

**Referencia**: RFC 5958

Formato **genérico** (no específico para RSA) para claves privadas. Encapsula la clave con un identificador de algoritmo, lo que permite distinguir claves de diferentes algoritmos.

```
-----BEGIN PRIVATE KEY-----
(datos codificados en Base64)
-----END PRIVATE KEY-----
```

Ventajas:
- Soporta cifrado de la clave privada en sí misma (`EncryptedPrivateKeyInfo`).
- Portabilidad entre diferentes algoritmos.

#### 5.6.3 X.509 (SubjectPublicKeyInfo)

**Referencia**: RFC 5280

Formato **genérico** para claves públicas, ampliamente usado en certificados digitales. Encapsula la clave pública con un identificador de algoritmo.

```
-----BEGIN PUBLIC KEY-----
(datos codificados en Base64)
-----END PUBLIC KEY-----
```

#### Comparación de Formatos

| Formato | Tipo de Clave | ¿Específico para RSA? | Encabezado PEM |
|---|---|---|---|
| PKCS#1 | Pública y Privada | Sí | `BEGIN RSA PUBLIC KEY` / `BEGIN RSA PRIVATE KEY` |
| PKCS#8 | Solo Privada | No (genérico) | `BEGIN PRIVATE KEY` |
| X.509 | Solo Pública | No (genérico) | `BEGIN PUBLIC KEY` |

### 5.7 Consideraciones de Seguridad

- **Tamaño mínimo de clave**: usa al menos **2048 bits**. Las claves de 1024 bits se consideran obsoletas.
- **Siempre usa OAEP**: evita PKCS#1 v1.5 para cifrado en nuevos proyectos debido a la vulnerabilidad Bleichenbacher.
- **No cifres datos grandes directamente**: el RSA está limitado por el tamaño de la clave. Para datos más grandes, usa criptografía híbrida (sección 2.4).
- **Generación de primos**: la calidad del generador de números aleatorios es crítica. Primos predecibles comprometen completamente la seguridad.
- **Amenaza cuántica**: el **algoritmo de Shor** permite que una computadora cuántica suficientemente grande factorice números enteros en tiempo polinomial, lo que rompería el RSA. Aunque computadoras cuánticas de esa capacidad aún no existen, organizaciones sensibles ya están planificando la migración a algoritmos post-cuánticos (como los seleccionados por el NIST: CRYSTALS-Kyber para cifrado y CRYSTALS-Dilithium para firmas).

---

## 6. Cuándo Usar AES vs RSA

### 6.1 Escenarios para AES

- **Cifrado de archivos y bases de datos**: grandes volúmenes de datos donde la velocidad es esencial.
- **Tráfico de red**: después de la negociación de claves (TLS), todo el tráfico se cifra con AES.
- **Cifrado de disco**: soluciones como BitLocker, FileVault y LUKS usan AES.
- **Cuando ambas partes ya comparten una clave**: no hay necesidad de intercambio de claves.

### 6.2 Escenarios para RSA

- **Intercambio de claves**: enviar una clave AES de forma segura a otra parte.
- **Firmas digitales**: firmar documentos, código o certificados.
- **Autenticación basada en certificados**: TLS, SSH, certificados X.509.
- **Cuando las partes no poseen un secreto compartido**: la clave pública puede distribuirse abiertamente.

### 6.3 Tabla de Decisión

| Necesidad | Algoritmo Recomendado |
|---|---|
| Cifrar grandes volúmenes de datos | AES (preferiblemente GCM) |
| Intercambiar claves con seguridad | RSA-OAEP |
| Firmar datos digitalmente | RSA + SHA-256 (o superior) |
| Cifrar y autenticar simultáneamente | AES-GCM o AES-CCM |
| Cifrar datos y enviar a desconocidos | Criptografía híbrida (RSA + AES) |
| Almacenar contraseñas | No uses AES ni RSA — usa Argon2, bcrypt o PBKDF2 |

---

## 7. Referencias

### Estándares NIST (FIPS)

- [**FIPS 197**](https://csrc.nist.gov/pubs/fips/197/final) — Advanced Encryption Standard (AES). NIST, 2001 (actualizado 2023).
- [**FIPS 180-4**](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) — Secure Hash Standard (SHS): SHA-1, SHA-224, SHA-256, SHA-384, SHA-512. NIST, 2015.
- [**FIPS 202**](https://csrc.nist.gov/pubs/fips/202/final) — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions. NIST, 2015.

### Publicaciones Especiales NIST (SP)

- [**NIST SP 800-38A**](https://csrc.nist.gov/pubs/sp/800/38/a/final) — Recommendation for Block Cipher Modes of Operation: Methods and Techniques (ECB, CBC, CFB, OFB, CTR). NIST, 2001.
- [**NIST SP 800-38C**](https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final) — Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality. NIST, 2004.
- [**NIST SP 800-38D**](https://csrc.nist.gov/pubs/sp/800/38/d/final) — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC. NIST, 2007.
- [**NIST SP 800-57 Part 1 Rev. 5**](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) — Recommendation for Key Management: Part 1 – General. NIST, 2020.

### RFCs (IETF)

- [**RFC 8017**](https://datatracker.ietf.org/doc/html/rfc8017) — PKCS #1: RSA Cryptography Specifications Version 2.2. IETF, 2016.
- [**RFC 3447**](https://datatracker.ietf.org/doc/html/rfc3447) — Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1. IETF, 2003.
- [**RFC 2437**](https://datatracker.ietf.org/doc/html/rfc2437) — PKCS #1: RSA Cryptography Specifications Version 2.0. IETF, 1998.
- [**RFC 5652**](https://datatracker.ietf.org/doc/html/rfc5652) — Cryptographic Message Syntax (CMS). IETF, 2009.
- [**RFC 5958**](https://datatracker.ietf.org/doc/html/rfc5958) — Asymmetric Key Packages (PKCS#8). IETF, 2010.
- [**RFC 5280**](https://datatracker.ietf.org/doc/html/rfc5280) — Internet X.509 Public Key Infrastructure Certificate and CRL Profile. IETF, 2008.
- [**RFC 3610**](https://datatracker.ietf.org/doc/html/rfc3610) — Counter with CBC-MAC (CCM). IETF, 2003.
