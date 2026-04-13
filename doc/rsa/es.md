# RSA (Rivest-Shamir-Adleman)

## Tabla de Contenidos

- [1. ¿Qué es RSA?](#1-qué-es-rsa)
- [2. Historia](#2-historia)
- [3. Cómo Funciona](#3-cómo-funciona)
- [4. Tamaños de Clave](#4-tamaños-de-clave)
- [5. Esquemas de Padding](#5-esquemas-de-padding)
- [6. Algoritmos de Hash Usados con RSA](#6-algoritmos-de-hash-usados-con-rsa)
- [7. Formatos de Clave](#7-formatos-de-clave)
- [8. Consideraciones de Seguridad](#8-consideraciones-de-seguridad)
- [9. Referencias](#9-referencias)

---

## 1. ¿Qué es RSA?

El RSA es el algoritmo de criptografía asimétrica más conocido y utilizado. Puede usarse tanto para **cifrado** como para **firmas digitales**.

---

## 2. Historia

En **1977**, tres investigadores del MIT — **Ron Rivest**, **Adi Shamir** y **Leonard Adleman** — publicaron el primer criptosistema de clave pública práctico. Rivest y Shamir, ambos científicos de la computación, proponían funciones candidatas, mientras Adleman, matemático, intentaba romperlas. Después de 42 intentos fallidos, en abril de 1977, Rivest formalizó la idea que se convertiría en el RSA.

El algoritmo fue publicado en la revista **Scientific American** en 1977 y rápidamente se convirtió en el estándar para la criptografía de clave pública. La patente estadounidense del RSA expiró en **septiembre de 2000**, haciéndolo libre para su uso en todo el mundo.

El nombre "RSA" proviene de las iniciales de los apellidos de los tres creadores: **R**ivest, **S**hamir y **A**dleman.

---

## 3. Cómo Funciona

La seguridad del RSA se basa en un problema matemático: la **dificultad de factorizar el producto de dos números primos muy grandes**. Multiplicar dos primos es rápido, pero dado solo el resultado, encontrar los factores originales es computacionalmente inviable para números suficientemente grandes.

### Generación de Claves

1. Se eligen dos números primos grandes **p** y **q** (cada uno con cientos de dígitos).
2. Se calcula **n = p × q** (el módulo). Este valor es público.
3. Se calcula **φ(n) = (p − 1) × (q − 1)** (la función totiente de Euler).
4. Se elige un exponente público **e**, coprimo a φ(n). El valor más utilizado es **e = 65537** (0x10001), elegido por ser primo y tener pocos bits activos (eficiente para la exponenciación).
5. Se calcula el exponente privado **d = e⁻¹ mod φ(n)** (el inverso modular de e).

- **Clave pública**: (n, e)
- **Clave privada**: (n, d)

### Cifrado y Descifrado

- **Cifrar**: c = m^e mod n (donde m es el mensaje numérico y c es el texto cifrado)
- **Descifrar**: m = c^d mod n

La seguridad depende del hecho de que, sin conocer p y q (que componen d), es computacionalmente inviable calcular d a partir de solo (n, e).

---

## 4. Tamaños de Clave

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

El tamaño de la clave también limita el **tamaño máximo de los datos** que pueden ser cifrados directamente (detallado en la sección 5).

---

## 5. Esquemas de Padding

En RSA, el mensaje en texto claro necesita ser transformado en un número entre 0 y n−1 antes del cifrado. El **padding** (o esquema de codificación) es el proceso que realiza esta transformación de forma segura. Cifrar sin padding (llamado "textbook RSA") es extremadamente inseguro.

### 5.1 PKCS#1 v1.5

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

### 5.2 OAEP (Optimal Asymmetric Encryption Padding)

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

### Versiones de OAEP

| Versión | Referencia | Detalles |
|---|---|---|
| OAEP v1 | Bellare-Rogaway (1994) | Propuesta original con SHA-1 |
| OAEP v2.0 | PKCS#1 v2.0 (RFC 2437) | Incorporación al estándar PKCS#1 con MGF1 |
| OAEP v2.1 | PKCS#1 v2.1 (RFC 3447) / v2.2 (RFC 8017) | **Recomendado** — hash configurable, MGF1, soporte de etiqueta |

> **Recomendación**: usa siempre **OAEP v2.1** (o posterior) con **SHA-256** o superior. Según la RFC 8017: *"RSAES-OAEP is required to be supported for new applications"*.

---

## 6. Algoritmos de Hash Usados con RSA

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

---

## 7. Formatos de Clave

Las claves RSA pueden almacenarse y transmitirse en diferentes formatos estandarizados. Cada formato tiene un propósito específico.

### 7.1 PKCS#1

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

### 7.2 PKCS#8 (PrivateKeyInfo)

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

### 7.3 X.509 (SubjectPublicKeyInfo)

**Referencia**: RFC 5280

Formato **genérico** para claves públicas, ampliamente usado en certificados digitales. Encapsula la clave pública con un identificador de algoritmo.

```
-----BEGIN PUBLIC KEY-----
(datos codificados en Base64)
-----END PUBLIC KEY-----
```

### Comparación de Formatos

| Formato | Tipo de Clave | ¿Específico para RSA? | Encabezado PEM |
|---|---|---|---|
| PKCS#1 | Pública y Privada | Sí | `BEGIN RSA PUBLIC KEY` / `BEGIN RSA PRIVATE KEY` |
| PKCS#8 | Solo Privada | No (genérico) | `BEGIN PRIVATE KEY` |
| X.509 | Solo Pública | No (genérico) | `BEGIN PUBLIC KEY` |

---

## 8. Consideraciones de Seguridad

- **Tamaño mínimo de clave**: usa al menos **2048 bits**. Las claves de 1024 bits se consideran obsoletas.
- **Siempre usa OAEP**: evita PKCS#1 v1.5 para cifrado en nuevos proyectos debido a la vulnerabilidad Bleichenbacher.
- **No cifres datos grandes directamente**: el RSA está limitado por el tamaño de la clave. Para datos más grandes, usa criptografía híbrida.
- **Generación de primos**: la calidad del generador de números aleatorios es crítica. Primos predecibles comprometen completamente la seguridad.
- **Amenaza cuántica**: el **algoritmo de Shor** permite que una computadora cuántica suficientemente grande factorice números enteros en tiempo polinomial, lo que rompería el RSA. Aunque computadoras cuánticas de esa capacidad aún no existen, organizaciones sensibles ya están planificando la migración a algoritmos post-cuánticos (como los seleccionados por el NIST: CRYSTALS-Kyber para cifrado y CRYSTALS-Dilithium para firmas).

---

## 9. Referencias

- [RFC 8017 — PKCS#1 v2.2](https://datatracker.ietf.org/doc/html/rfc8017)
- [RFC 3447 — PKCS#1 v2.1](https://datatracker.ietf.org/doc/html/rfc3447)
- [RFC 2437 — PKCS#1 v2.0](https://datatracker.ietf.org/doc/html/rfc2437)
- [RFC 5958 — PKCS#8](https://datatracker.ietf.org/doc/html/rfc5958)
- [RFC 5280 — X.509](https://datatracker.ietf.org/doc/html/rfc5280)
- [NIST SP 800-57 — Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
