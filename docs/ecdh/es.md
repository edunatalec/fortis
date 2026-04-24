# ECDH (Elliptic Curve Diffie-Hellman)

## Índice

- [1. ¿Qué es ECDH?](#1-qué-es-ecdh)
- [2. Cómo Funciona](#2-cómo-funciona)
- [3. Curvas Recomendadas](#3-curvas-recomendadas)
- [4. ¿Por qué Usar una KDF (Función de Derivación de Claves)?](#4-por-qué-usar-una-kdf-función-de-derivación-de-claves)
- [5. ECDH + Cifrado Simétrico](#5-ecdh--cifrado-simétrico)
- [6. Esquemas de Acuerdo de Claves](#6-esquemas-de-acuerdo-de-claves)
- [7. Formatos de Claves](#7-formatos-de-claves)
- [8. Consideraciones de Seguridad](#8-consideraciones-de-seguridad)
- [9. Casos de Uso](#9-casos-de-uso)
- [10. Referencias](#10-referencias)

---

## 1. ¿Qué es ECDH?

### 1.1 Definición

ECDH es un **protocolo de acuerdo de claves** basado en criptografía de curvas elípticas. A diferencia de RSA (que cifra datos directamente), ECDH permite que dos partes deriven de forma independiente el mismo **secreto compartido** a través de un canal inseguro. Ninguna de las partes envía el secreto -- ambas lo calculan a partir de su propia clave privada y la clave pública de la otra parte.

Analogía: imagina que dos personas mezclan cada una un color secreto con un color público compartido. Intercambian las mezclas. Cada persona entonces mezcla su propio color secreto con la mezcla que recibió. Ambas llegan al mismo color final -- pero un observador que solo vio las mezclas intercambiadas no puede determinar el color final. ECDH funciona con el mismo principio, pero con matemáticas de curvas elípticas en lugar de colores.

### 1.2 Acuerdo de Claves vs Cifrado

Es esencial entender que ECDH **no cifra datos directamente**. Produce un secreto compartido que luego se usa con un **algoritmo simétrico** (como AES) para cifrar datos. Esto es fundamentalmente diferente de RSA, que puede cifrar datos directamente (dentro de los límites de tamaño de clave).

| Característica | ECDH | RSA |
|---|---|---|
| Propósito | Acuerdo de claves | Cifrado y firmas |
| ¿Cifra datos directamente? | No | Sí (limitado por tamaño de clave) |
| Salida | Secreto compartido (bytes crudos) | Texto cifrado |
| ¿Requiere cifrado simétrico? | Sí, siempre | No (pero híbrido es recomendado) |
| Número de participantes | Exactamente 2 | 1 emisor, 1 receptor |

Esto significa que ECDH siempre se usa como **parte de un protocolo más amplio**: ECDH produce el secreto compartido, una KDF deriva una clave a partir de él, y un cifrado simétrico (como AES-GCM) cifra los datos reales.

### 1.3 Fundamento Matemático

La seguridad de ECDH se basa en el **Problema del Logaritmo Discreto de Curvas Elípticas (ECDLP)**. Una curva elíptica sobre un campo finito se define por una ecuación de la forma:

```
y^2 = x^3 + ax + b  (mod p)
```

En dicha curva, se define una operación especial llamada **multiplicación de puntos**: dado un punto base G y un escalar d, podemos calcular Q = d * G (sumando G consigo mismo d veces usando la ley de grupo de la curva). Esta operación es eficiente de calcular.

Sin embargo, el **problema inverso** -- dado Q y G, encontrar d -- es computacionalmente inviable para curvas grandes. Este es el ECDLP. El mejor ataque conocido es el **algoritmo rho de Pollard** con complejidad O(sqrt(n)), lo que significa que una curva de n bits proporciona aproximadamente **n/2 bits de seguridad**.

Para comparar, la seguridad de RSA se basa en la factorización de enteros, donde existen ataques sub-exponenciales (criba general del cuerpo de números). Por esto ECC logra seguridad equivalente con tamaños de clave dramáticamente menores.

---

## 2. Cómo Funciona

El proceso de acuerdo de claves ECDH sigue estos pasos:

### Paso a Paso

1. **Ambas partes acuerdan los parámetros de la curva**: una curva elíptica E definida sobre un campo finito, y un punto base G de orden primo n. Estos parámetros son públicos y estandarizados (por ejemplo, NIST P-256).

2. **La Parte A genera un par de claves**:
   - Elige una clave privada aleatoria d_A en el rango [1, n-1].
   - Calcula la clave pública Q_A = d_A * G.

3. **La Parte B genera un par de claves**:
   - Elige una clave privada aleatoria d_B en el rango [1, n-1].
   - Calcula la clave pública Q_B = d_B * G.

4. **Intercambian claves públicas**: Q_A y Q_B se envían a través del canal (posiblemente inseguro). Las claves privadas d_A y d_B **nunca se transmiten**.

5. **La Parte A calcula el secreto compartido**:
   - S = d_A * Q_B = d_A * (d_B * G)

6. **La Parte B calcula el secreto compartido**:
   - S = d_B * Q_A = d_B * (d_A * G)

7. **Ambas llegan al mismo punto S**: porque la multiplicación escalar en curvas elípticas es asociativa y conmutativa, d_A * (d_B * G) = d_B * (d_A * G).

8. **El secreto compartido** es la coordenada x del punto S.

### Diagrama Visual

```
Parte A                              Parte B
-------                              -------
d_A (privada)                       d_B (privada)
Q_A = d_A * G                      Q_B = d_B * G
        ---- Q_A ---->
        <---- Q_B ----
S = d_A * Q_B                      S = d_B * Q_A
    = d_A * d_B * G                    = d_B * d_A * G
    (mismo punto!)                      (mismo punto!)
```

Un espía que observe Q_A y Q_B no puede calcular S sin conocer d_A o d_B. Para hacerlo, necesitaría resolver el ECDLP, lo cual es computacionalmente inviable para curvas de tamaño adecuado.

### Por Qué es Seguro

La seguridad proviene del hecho de que mientras calcular Q = d * G es fácil (tiempo polinomial), recuperar d a partir de Q y G es difícil (tiempo exponencial para curvas adecuadamente elegidas). Un atacante que observe Q_A = d_A * G y Q_B = d_B * G no puede calcular eficientemente d_A * d_B * G sin conocer al menos uno de los escalares privados.

Esto se formaliza como la **suposición Computational Diffie-Hellman (CDH)** sobre curvas elípticas: dados G, d_A * G, y d_B * G, es inviable calcular d_A * d_B * G.

---

## 3. Curvas Recomendadas

NIST ha estandarizado varias curvas elípticas para uso criptográfico. La siguiente tabla compara las tres curvas NIST principales:

| Curva | Tamaño del Campo | Nivel de Seguridad | Tamaño de Clave ECC | Clave RSA Equivalente | Proporción RSA:ECC |
|---|---|---|---|---|---|
| P-256 (secp256r1) | 256 bits | 128 bits | 256 bits | 3072 bits | 12:1 |
| P-384 (secp384r1) | 384 bits | 192 bits | 384 bits | 7680 bits | 20:1 |
| P-521 (secp521r1) | 521 bits | ~260 bits | 521 bits | 15360 bits | ~29:1 |

La observación clave aquí es que ECC proporciona **seguridad equivalente con tamaños de clave dramáticamente menores**. Con seguridad de 128 bits, una clave ECC es de 256 bits versus 3072 bits de RSA -- una proporción de 12:1. Esto se traduce en cálculos más rápidos, menos ancho de banda y certificados más pequeños.

### Cómo Elegir

- **P-256**: la curva más utilizada. Proporciona seguridad de 128 bits, lo cual se considera suficiente para la mayoría de las aplicaciones actuales y en el futuro previsible. Es la opción predeterminada para TLS 1.3, y se beneficia de aceleración por hardware en procesadores modernos.

- **P-384**: proporciona seguridad de 192 bits. Se usa cuando regulaciones o requisitos de cumplimiento exigen un mayor margen de seguridad (por ejemplo, ciertos sistemas gubernamentales o financieros).

- **P-521**: proporciona aproximadamente 260 bits de seguridad. Raramente necesaria en la práctica -- la seguridad de 128 bits ya está más allá del alcance de fuerza bruta. Sin embargo, puede elegirse para un margen de seguridad máximo en claves de larga duración.

> **Recomendación**: usa **P-256** para uso general. Es la más ampliamente soportada, la más eficiente, y proporciona un amplio margen de seguridad.

### Una Nota sobre Curve25519

Aunque no es una curva NIST, **Curve25519** (usada a través de la función de intercambio de claves X25519) merece mención. Diseñada por Daniel J. Bernstein, proporciona aproximadamente 128 bits de seguridad y es ampliamente utilizada en protocolos modernos (TLS 1.3, Signal, WireGuard). Su diseño prioriza la resistencia a errores de implementación y ataques de canal lateral.

---

## 4. ¿Por qué Usar una KDF (Función de Derivación de Claves)?

El secreto compartido crudo producido por ECDH **nunca** debe usarse directamente como clave criptográfica. Siempre debe aplicarse primero una **Función de Derivación de Claves (KDF)**.

### Razones

1. **Distribución no uniforme**: la coordenada x del punto compartido está sesgada por la estructura de la curva. No está uniformemente distribuida entre todas las cadenas de bits posibles de su longitud, lo que significa que usarla directamente como clave introduciría debilidades sutiles.

2. **Vinculación de contexto**: una KDF puede vincular la clave derivada a información de contexto específica -- identificadores de las partes, identificadores de algoritmos, nonces y datos de sesión. Esto evita que un atacante reutilice un secreto compartido en un contexto diferente.

3. **Separación de claves**: a partir de un único secreto compartido, una KDF puede derivar múltiples claves independientes para diferentes propósitos (por ejemplo, una clave para cifrado, otra para autenticación). Sin una KDF, usar el mismo secreto crudo para múltiples propósitos crearía dependencias cruzadas peligrosas.

4. **Soporte de secreto hacia adelante**: cuando se usa con claves efímeras, cada sesión produce material de claves independiente. La KDF asegura que las claves derivadas sean criptográficamente independientes incluso si los secretos compartidos están relacionados.

### HKDF (RFC 5869)

**HKDF** (Función de Derivación de Claves basada en HMAC) es la KDF recomendada para uso con ECDH. Opera en dos fases:

1. **Extraer**: toma el material de entrada de claves no uniforme (IKM) y una sal opcional, y produce una clave pseudoaleatoria (PRK):
   ```
   PRK = HMAC-Hash(sal, IKM)
   ```
   La sal debe ser un valor aleatorio o pseudoaleatorio. Si no está disponible, puede usarse una cadena de ceros de longitud igual a la salida del hash.

2. **Expandir**: toma el PRK e información opcional de contexto/aplicación (info), y produce el material de claves de salida (OKM) de la longitud deseada:
   ```
   T(1) = HMAC-Hash(PRK, info || 0x01)
   T(2) = HMAC-Hash(PRK, T(1) || info || 0x02)
   OKM = primeros L bytes de T(1) || T(2) || ...
   ```

**SHA-256** es la opción de hash estándar para HKDF. El parámetro info debe incluir identificadores de ambas partes y el uso previsto de la clave.

---

## 5. ECDH + Cifrado Simétrico

### 5.1 Combinación Recomendada con AES

AES es la opción natural para el paso de cifrado simétrico porque está aprobado por NIST, se beneficia de aceleración por hardware (AES-NI), es extremadamente rápido y es universalmente soportado en todas las plataformas y lenguajes.

La siguiente tabla muestra la combinación recomendada entre curvas ECDH y tamaños de clave AES, igualando sus niveles de seguridad:

| Curva | AES Recomendado | Correspondencia de Seguridad |
|---|---|---|
| P-256 | AES-128 | 128 bits <-> 128 bits |
| P-384 | AES-192 o AES-256 | 192 bits <-> 192/256 bits |
| P-521 | AES-256 | ~260 bits <-> 256 bits |

**AES-GCM** es el modo recomendado, ya que proporciona tanto confidencialidad como autenticación (AEAD -- Cifrado Autenticado con Datos Asociados). Esto significa que no solo cifra los datos sino que también produce una etiqueta de autenticación que detecta cualquier adulteración.

### 5.2 Otros Algoritmos Simétricos

ECDH no está limitado a AES. El secreto compartido, una vez procesado a través de una KDF, produce bytes de clave crudos que pueden usarse con **cualquier** cifrado simétrico. Otras opciones incluyen:

- **ChaCha20-Poly1305**: una alternativa popular a AES-GCM, ampliamente usada en TLS 1.3. Es particularmente eficiente en software en plataformas sin aceleración de hardware AES.
- **Camellia**: una alternativa aprobada por NIST a AES con una estructura de cifrado de bloques similar.
- Cualquier otro cifrado simétrico que acepte material de claves de la longitud apropiada.

La elección del algoritmo simétrico es **independiente** de ECDH -- la KDF produce bytes de clave crudos que pueden alimentarse a cualquier cifrado.

### 5.3 Flujo Práctico

El flujo completo desde el intercambio de claves hasta la comunicación cifrada:

```
1. Intercambio de Claves (una vez):
   App     -> genera (privA, pubA), envía pubA al Backend
   Backend -> genera (privB, pubB), envía pubB a la App
   Ambos derivan: secretoCompartido = ECDH(miPrivada, suPublica)
   Ambos derivan: claveAes = HKDF(secretoCompartido)

2. Comunicación (cada mensaje):
   Emisor:   textoCifrado = AES-GCM(claveAes, textoClaro)
   Receptor: textoClaro   = AES-GCM(claveAes, textoCifrado)
```

Este es el patrón de cifrado híbrido: ECDH maneja el acuerdo de claves (resolviendo el problema de distribución de claves), y AES maneja el cifrado masivo de datos (rápido, sin límites de tamaño).

---

## 6. Esquemas de Acuerdo de Claves

NIST SP 800-56A define varios esquemas de acuerdo de claves basados en los tipos de claves usados por cada parte. La distinción es entre claves **efímeras** (generadas frescas para cada sesión) y claves **estáticas** (de larga duración, almacenadas de forma persistente).

| Esquema | Descripción | Secreto Hacia Adelante |
|---|---|---|
| dhEphem (C(2e, 0s)) | Ambas partes usan solo claves efímeras | Sí |
| dhOneFlow (C(1e, 1s)) | Una parte efímera, una estática | Parcial |
| dhStatic (C(0e, 2s)) | Ambas partes usan claves estáticas | No |
| dhHybrid1 (C(2e, 2s)) | Combinación de claves efímeras y estáticas | Sí |

### Claves Efímeras vs Estáticas

- Las **claves efímeras** se generan frescas para cada sesión y se destruyen después de calcular el secreto compartido. Proporcionan **secreto hacia adelante**: si una clave privada de largo plazo es comprometida en el futuro, las sesiones pasadas permanecen seguras porque las claves efímeras ya no existen.

- Las **claves estáticas** son de larga duración y se reutilizan entre sesiones. Son más simples de gestionar (no es necesario generar nuevas claves para cada sesión) pero **no** proporcionan secreto hacia adelante: si la clave privada estática es comprometida, todas las sesiones pasadas que usaron esa clave pueden ser descifradas.

### Elegir un Esquema

- **dhEphem (C(2e, 0s))**: ambas partes generan pares de claves frescos para cada sesión. Esta es la opción más fuerte y es utilizada en TLS 1.3. Sin embargo, no proporciona confirmación de claves ni autenticación de identidad por si misma -- estas deben provenir de mecanismos adicionales (por ejemplo, firmas digitales en las claves públicas efímeras).

- **dhOneFlow (C(1e, 1s))**: una parte (típicamente un servidor) tiene una clave estática, mientras que la otra (típicamente un cliente) usa una clave efímera. Esto proporciona secreto hacia adelante parcial -- si la clave estática del servidor es comprometida, las sesiones pasadas quedan expuestas, pero si la clave efímera del cliente es segura, la sesión actual está protegida.

- **dhStatic (C(0e, 2s))**: ambas partes usan claves estáticas. El secreto compartido es el mismo para cada sesión entre las mismas dos partes. Sin secreto hacia adelante. Útil solo en entornos restringidos donde la generación de claves por sesión es impracticable.

- **dhHybrid1 (C(2e, 2s))**: combina tanto claves efímeras como estáticas. El secreto compartido final incorpora ambas. Proporciona secreto hacia adelante y también permite autenticación a través de las claves estáticas.

---

## 7. Formatos de Claves

### 7.1 Formatos de Clave Pública

| Formato | Descripción | Encabezado PEM |
|---|---|---|
| X.509 (SubjectPublicKeyInfo) | Formato estándar con identificador de algoritmo y OID de curva | `BEGIN PUBLIC KEY` |
| Punto No Comprimido | Bytes crudos: 0x04 || x || y | N/A (bytes crudos) |

#### X.509 (SubjectPublicKeyInfo)

Este es el formato estándar para claves públicas EC, análogo al formato X.509 usado para claves públicas RSA. Envuelve el punto público crudo con un identificador de algoritmo que especifica tanto el tipo de clave (EC) como la curva.

Estructura ASN.1:

```
SEQUENCE {
  SEQUENCE {                    -- AlgorithmIdentifier
    OID 1.2.840.10045.2.1      -- id-ecPublicKey
    OID <curve-oid>             -- namedCurve (ej., 1.2.840.10045.3.1.7 para P-256)
  }
  BIT STRING <0x04 || x || y>  -- punto no comprimido
}
```

Codificación PEM:

```
-----BEGIN PUBLIC KEY-----
(Datos DER codificados en Base64)
-----END PUBLIC KEY-----
```

#### Formato de Punto No Comprimido

La clave pública cruda se representa como un único byte 0x04 (indicando formato no comprimido) seguido de las coordenadas x e y del punto, cada una rellenada al tamaño del campo:

```
04 || coordenada-x || coordenada-y
```

Para P-256, esto es 1 + 32 + 32 = 65 bytes. Para P-384, es 1 + 48 + 48 = 97 bytes. Para P-521, es 1 + 66 + 66 = 133 bytes.

### 7.2 Formatos de Clave Privada

| Formato | Descripción | Encabezado PEM |
|---|---|---|
| PKCS#8 (PrivateKeyInfo) | Formato genérico estándar con identificador de algoritmo | `BEGIN PRIVATE KEY` |
| SEC1 (RFC 5915) | Formato específico de EC con curva y clave pública opcionales | `BEGIN EC PRIVATE KEY` |

#### PKCS#8 (PrivateKeyInfo)

El formato genérico de clave privada, idéntico en concepto al formato PKCS#8 usado para RSA. Envuelve los datos de clave específicos de EC con un identificador de algoritmo.

```
-----BEGIN PRIVATE KEY-----
(Datos DER codificados en Base64)
-----END PRIVATE KEY-----
```

Ventajas:
- Agnóstico de algoritmo: el mismo formato se usa para RSA, EC y otros tipos de claves.
- Soporta cifrado de la propia clave privada (EncryptedPrivateKeyInfo).
- Ampliamente soportado en todas las plataformas y bibliotecas.

#### SEC1 (RFC 5915)

Un formato específico de EC que contiene el escalar privado d y opcionalmente incluye los parámetros de la curva y la clave pública correspondiente.

Estructura ASN.1:

```
SEQUENCE {
  INTEGER 1                        -- version
  OCTET STRING <clave-privada-d>   -- clave privada (rellenada al tamaño del campo)
  [0] OID <curve-oid>              -- parámetros (opcional)
  [1] BIT STRING <punto-público>   -- clavePublica (opcional)
}
```

Codificación PEM:

```
-----BEGIN EC PRIVATE KEY-----
(Datos DER codificados en Base64)
-----END EC PRIVATE KEY-----
```

### Comparación de Formatos

| Formato | Tipo de Clave | Específico de EC? | Encabezado PEM |
|---|---|---|---|
| X.509 | Solo pública | No (genérico) | `BEGIN PUBLIC KEY` |
| Punto No Comprimido | Solo pública | Sí | N/A (bytes crudos) |
| PKCS#8 | Solo privada | No (genérico) | `BEGIN PRIVATE KEY` |
| SEC1 | Solo privada | Sí | `BEGIN EC PRIVATE KEY` |

---

## 8. Consideraciones de Seguridad

1. **Siempre validar las claves públicas** (obligatorio según NIST SP 800-56A Sección 5.6.2.3):
   - Verificar que el punto no es el punto en el infinito.
   - Verificar que el punto está en la curva (satisface la ecuación de la curva).
   - Verificar n * Q = O (el punto está en el subgrupo correcto de orden primo).
   - No validar habilita **ataques de curva inválida**, donde un atacante envía un punto cuidadosamente elaborado que se encuentra en una curva diferente (más débil), potencialmente permitiendo la recuperación de la clave privada.

2. **Siempre aplicar una KDF**: nunca usar el secreto compartido crudo directamente como clave criptográfica. La coordenada x del punto compartido no está uniformemente distribuida y carece de vinculación de contexto (ver sección 4).

3. **Usar solo curvas aprobadas**: P-256, P-384 y P-521 de NIST SP 800-186. Evitar curvas no estándar o en desuso.

4. **Usar un RNG criptográficamente seguro**: las claves privadas deben generarse usando un generador de números aleatorios conforme a NIST SP 800-90A. La aleatoriedad débil compromete completamente la seguridad del protocolo -- si un atacante puede predecir o reducir el espacio de claves privadas, el ECDLP se vuelve resoluble.

5. **Destruir las claves privadas efímeras**: después de calcular el secreto compartido, las claves privadas efímeras deben destruirse inmediatamente. Retenerlas anula el beneficio de secreto hacia adelante del acuerdo de claves efímero.

6. **Incluir contexto en la KDF**: vincular las claves derivadas al contexto del protocolo a través del parámetro info de HKDF. Esto debe incluir identificadores de las partes, identificadores de algoritmos y datos específicos de sesión para prevenir ataques entre protocolos.

7. **Verificar la salida cero**: verificar que el secreto compartido no es el punto en el infinito (coordenada x todo ceros). Un secreto compartido cero indica un **ataque de subgrupo pequeño** y el intercambio de claves debe abortarse.

8. **Igualar niveles de seguridad**: usar niveles de seguridad consistentes en todos los componentes. No combinar P-256 (seguridad de 128 bits) con AES-256 (seguridad de 256 bits) -- la seguridad general está limitada por el eslabón más débil. P-256 debe combinarse con AES-128, P-384 con AES-192 o AES-256, y P-521 con AES-256.

---

## 9. Casos de Uso

ECDH (y su variante efímera ECDHE) se usa en virtualmente todos los protocolos de seguridad modernos:

- **TLS 1.3** (RFC 8446): ECDHE es obligatorio para el intercambio de claves. El transporte de claves RSA estático fue eliminado completamente en TLS 1.3. Los grupos soportados incluyen x25519, secp256r1, secp384r1 y secp521r1.

- **Protocolo Signal**: usa X25519 (Diffie-Hellman basado en Curve25519) para X3DH (Extended Triple Diffie-Hellman) como acuerdo de claves inicial y para el Double Ratchet DH continuo que proporciona secreto hacia adelante para cada mensaje.

- **WireGuard VPN**: usa X25519 para su patrón de handshake Noise_IKpsk2, estableciendo un túnel seguro con mínimas ida y vuelta.

- **SSH** (RFC 5656, RFC 8731): intercambio de claves ECDH con curvas NIST (ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521) y curve25519 (curve25519-sha256).

- **ECIES** (Esquema de Cifrado Integrado de Curvas Elípticas): combina ECDH + KDF + cifrado simétrico + MAC en un esquema de cifrado híbrido completo. Definido en SEC 1 Sección 5.1. Es útil cuando una parte tiene una clave pública estática y la otra quiere cifrar un mensaje para ella sin interacción previa.

- **Bóvedas de contraseñas y aplicaciones seguras**: comunicación bidireccional entre una aplicación móvil y un backend usando ECDH para acuerdo de claves combinado con AES para cifrado de datos. La app y el backend intercambian claves públicas una vez, derivan una clave simétrica compartida, y luego cifran toda la comunicación subsiguiente con AES-GCM.

---

## 10. Referencias

### Estándares NIST

- [**NIST SP 800-56A Rev. 3**](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final) -- Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography. NIST, 2018.
- [**NIST SP 800-186**](https://csrc.nist.gov/pubs/sp/800/186/final) -- Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters. NIST, 2023.
- [**FIPS 186-5**](https://csrc.nist.gov/pubs/fips/186-5/final) -- Digital Signature Standard (DSS). NIST, 2023.
- [**NIST SP 800-57 Part 1 Rev. 5**](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) -- Recommendation for Key Management: Part 1 -- General. NIST, 2020.
- [**NIST SP 800-90A Rev. 1**](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) -- Recommendation for Random Number Generation Using Deterministic Random Bit Generators. NIST, 2015.

### RFCs (IETF)

- [**RFC 6090**](https://datatracker.ietf.org/doc/html/rfc6090) -- Fundamental Elliptic Curve Cryptography Algorithms. IETF, 2011.
- [**RFC 5869**](https://datatracker.ietf.org/doc/html/rfc5869) -- HMAC-based Extract-and-Expand Key Derivation Function (HKDF). IETF, 2010.
- [**RFC 7748**](https://datatracker.ietf.org/doc/html/rfc7748) -- Elliptic Curves for Security. IETF, 2016.
- [**RFC 5915**](https://datatracker.ietf.org/doc/html/rfc5915) -- Elliptic Curve Private Key Structure. IETF, 2010.
- [**RFC 8446**](https://datatracker.ietf.org/doc/html/rfc8446) -- The Transport Layer Security (TLS) Protocol Version 1.3. IETF, 2018.
- [**RFC 5656**](https://datatracker.ietf.org/doc/html/rfc5656) -- Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer. IETF, 2009.

### Estándares de la Industria

- [**SEC 1 v2**](https://www.secg.org/sec1-v2.pdf) -- Elliptic Curve Cryptography. SECG, 2009.
- [**SEC 2 v2**](https://www.secg.org/sec2-v2.pdf) -- Recommended Elliptic Curve Domain Parameters. SECG, 2010.
