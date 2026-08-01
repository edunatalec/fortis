# Criptografía

Una guía completa sobre criptografía, abarcando desde conceptos fundamentales hasta los principios detrás de las principales técnicas criptográficas.

## Índice

- [1. ¿Qué es la Criptografía?](#1-qué-es-la-criptografía)
- [2. Criptografía Simétrica vs Asimétrica](#2-criptografía-simétrica-vs-asimétrica)
- [3. Funciones Hash](#3-funciones-hash)
- [4. Casos de Uso de la Criptografía](#4-casos-de-uso-de-la-criptografía)
- [5. Cuándo Usar Cada Tipo](#5-cuándo-usar-cada-tipo)
- [6. Referencias](#6-referencias)

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

El algoritmo simétrico más utilizado actualmente es el **AES**.

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

El algoritmo asimétrico más utilizado es el **RSA**.

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
3. La **clave simétrica se cifra** con la clave pública del destinatario (resuelve la distribución).
4. El destinatario usa su **clave privada** para descifrar la clave simétrica.
5. Con la clave simétrica recuperada, el destinatario **descifra los datos**.

De esta forma, se obtiene lo mejor de ambos mundos: la velocidad de la criptografía simétrica y la seguridad en el intercambio de claves de la criptografía asimétrica.

---

## 3. Funciones Hash

Las funciones hash se usan frecuentemente en conjunto con algoritmos de criptografía y desempeñan un papel fundamental en muchos protocolos criptográficos. Por eso, es importante entenderlas como parte de cualquier base en criptografía.

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

---

## 4. Casos de Uso de la Criptografía

La criptografía es la columna vertebral de la seguridad digital moderna. A continuación se presentan los escenarios más comunes del mundo real donde se aplican técnicas criptográficas.

### 4.1 HTTPS/TLS (Protección del Tráfico Web)

Cada vez que ves el icono del candado en tu navegador, TLS (Transport Layer Security) está en acción. Utiliza una combinación de criptografía asimétrica (para el handshake inicial y el intercambio de claves) y criptografía simétrica (para cifrar el flujo real de datos). Esto protege todo, desde credenciales de inicio de sesión hasta compras en línea, contra la interceptación y la manipulación.

### 4.2 Cifrado de Extremo a Extremo (WhatsApp, Signal)

Aplicaciones de mensajería como WhatsApp y Signal implementan cifrado de extremo a extremo, lo que significa que solo el emisor y el destinatario pueden leer los mensajes. Ni siquiera el proveedor del servicio tiene acceso al contenido. Esto se logra mediante una combinación de protocolos de acuerdo de claves y cifrado simétrico, garantizando que los mensajes permanezcan privados durante todo su recorrido.

### 4.3 Bóvedas de Contraseñas

Los gestores de contraseñas como 1Password, Bitwarden y KeePass usan cifrado simétrico fuerte para proteger tus credenciales almacenadas. Una única contraseña maestra deriva una clave de cifrado (normalmente a través de PBKDF2 o Argon2), que luego cifra toda la bóveda. Sin la contraseña maestra, los datos almacenados son computacionalmente inaccesibles.

### 4.4 Firmas Digitales

Las firmas digitales usan criptografía asimétrica para garantizar la autoría e integridad de documentos, software y certificados. El firmante usa su clave privada para firmar un hash de los datos, y cualquier persona con la clave pública correspondiente puede verificar la firma. Esta es la base de la firma de código, las firmas de documentos PDF y la infraestructura de certificados X.509 que sostiene internet.

### 4.5 Cifrado de Disco/Almacenamiento

Las soluciones de cifrado de disco completo como BitLocker (Windows), FileVault (macOS) y LUKS (Linux) usan cifrado simétrico para proteger todos los datos en un dispositivo de almacenamiento. Si el dispositivo se pierde o es robado, los datos permanecen ilegibles sin las credenciales correctas. Esto es crítico para portátiles, unidades externas y cualquier dispositivo que pueda salir de un entorno seguro.

### 4.6 VPN (WireGuard, IPsec)

Las Redes Privadas Virtuales crean un túnel cifrado entre tu dispositivo y un servidor remoto, protegiendo todo el tráfico de red contra la interceptación. Los protocolos VPN modernos como WireGuard usan acuerdo de claves y cifrado simétrico de última generación para garantizar tanto el rendimiento como la seguridad. IPsec, otro protocolo ampliamente desplegado, usa una combinación de intercambio de claves y algoritmos simétricos para asegurar las comunicaciones de red en la capa IP.

---

## 5. Cuándo Usar Cada Tipo

Elegir el enfoque criptográfico correcto depende de tu escenario específico. Aquí tienes una guía práctica para decidir entre enfoques simétricos, asimétricos, híbridos y de acuerdo de claves.

### 5.1 Criptografía Simétrica

Usa algoritmos simétricos (como AES o ChaCha20) cuando:

- **Cifrar grandes volúmenes de datos**: archivos, bases de datos, cifrado de disco o flujos de red.
- **Ambas partes ya comparten una clave secreta**: no se necesita intercambio de claves.
- **El rendimiento es crítico**: el cifrado simétrico es órdenes de magnitud más rápido que el cifrado asimétrico.

### 5.2 Criptografía Asimétrica

Usa algoritmos asimétricos (como RSA o ECDSA) cuando:

- **Firmar datos digitalmente**: documentos, código, certificados — demostrando autoría e integridad.
- **Autenticación basada en certificados**: TLS, SSH, validación de certificados X.509.
- **Las partes no tienen un secreto precompartido**: la clave pública puede distribuirse abiertamente.

### 5.3 Criptografía Híbrida

Usa enfoques híbridos cuando:

- **Enviar datos cifrados a otra parte sin un secreto compartido**: genera una clave simétrica aleatoria, cifra los datos con ella y cifra la clave simétrica con la clave pública del destinatario.
- **Implementar protocolos de comunicación seguros**: TLS, PGP y S/MIME siguen este modelo.

### 5.4 Acuerdo de Claves

Usa protocolos de acuerdo de claves (como ECDH o X25519) cuando:

- **Establecer un secreto compartido sobre un canal inseguro**: ambas partes contribuyen a la creación de una clave compartida sin que esta sea transmitida.
- **Se requiere secreto hacia adelante** (*forward secrecy*): el acuerdo de claves efímero garantiza que comprometer una clave a largo plazo no comprometa sesiones pasadas.
- **Diseño de protocolos modernos**: WireGuard y TLS 1.3, por ejemplo, prefieren el intercambio de claves basado en ECDH sobre el transporte de claves RSA.

### 5.5 Tabla de Decisión

| Necesidad | Enfoque Recomendado |
|---|---|
| Cifrar grandes volúmenes de datos | Cifrado simétrico (ej., AES-GCM, ChaCha20-Poly1305) |
| Intercambiar claves con seguridad | Acuerdo de claves (ej., ECDH, X25519) o cifrado asimétrico (ej., RSA-OAEP) |
| Firmar datos digitalmente | Firmas asimétricas (ej., RSA + SHA-256, ECDSA, Ed25519) |
| Cifrar y autenticar simultáneamente | Cifrado simétrico autenticado (ej., AES-GCM, ChaCha20-Poly1305) |
| Cifrar datos y enviar a desconocidos | Criptografía híbrida (acuerdo de claves o asimétrico + simétrico) |
| Lograr secreto hacia adelante | Acuerdo de claves efímero (ej., ECDHE) |
| Almacenar contraseñas | No uses cifrado — usa Argon2, bcrypt o PBKDF2 |

---

## 6. Referencias

### Estándares NIST (FIPS)

- [**FIPS 180-4**](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) — Secure Hash Standard (SHS): SHA-1, SHA-224, SHA-256, SHA-384, SHA-512. NIST, 2015.
- [**FIPS 202**](https://csrc.nist.gov/pubs/fips/202/final) — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions. NIST, 2015.

### Publicaciones Especiales NIST (SP)

- [**NIST SP 800-57 Part 1 Rev. 5**](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) — Recommendation for Key Management: Part 1 – General. NIST, 2020.
