# ECDH (Elliptic Curve Diffie-Hellman)

## Sumário

- [1. O que é ECDH?](#1-o-que-é-ecdh)
- [2. Como Funciona](#2-como-funciona)
- [3. Curvas Recomendadas](#3-curvas-recomendadas)
- [4. Por que Usar uma KDF (Função de Derivação de Chaves)?](#4-por-que-usar-uma-kdf-função-de-derivação-de-chaves)
- [5. ECDH + Criptografia Simétrica](#5-ecdh--criptografia-simétrica)
- [6. Esquemas de Acordo de Chaves](#6-esquemas-de-acordo-de-chaves)
- [7. Formatos de Chaves](#7-formatos-de-chaves)
- [8. Considerações de Segurança](#8-considerações-de-segurança)
- [9. Casos de Uso](#9-casos-de-uso)
- [10. Referências](#10-referências)

---

## 1. O que é ECDH?

### 1.1 Definição

ECDH é um **protocolo de acordo de chaves** baseado em criptografia de curvas elípticas. Diferente do RSA (que cifra dados diretamente), o ECDH permite que duas partes derivem de forma independente o mesmo **segredo compartilhado** através de um canal inseguro. Nenhuma das partes envia o segredo -- ambas o calculam a partir de sua própria chave privada e da chave pública da outra parte.

Analogia: imagine que duas pessoas misturam cada uma uma cor secreta com uma cor pública compartilhada. Elas trocam as misturas. Cada pessoa então mistura sua própria cor secreta com a mistura que recebeu. Ambas chegam à mesma cor final -- mas um observador que viu apenas as misturas trocadas não consegue determinar a cor final. O ECDH funciona com o mesmo princípio, mas com matemática de curvas elípticas em vez de cores.

### 1.2 Acordo de Chaves vs Criptografia

É essencial entender que o ECDH **não cifra dados diretamente**. Ele produz um segredo compartilhado que é então usado com um **algoritmo simétrico** (como AES) para cifrar dados. Isso é fundamentalmente diferente do RSA, que pode cifrar dados diretamente (dentro dos limites de tamanho de chave).

| Característica | ECDH | RSA |
|---|---|---|
| Propósito | Acordo de chaves | Criptografia e assinaturas |
| Cifra dados diretamente? | Não | Sim (limitado pelo tamanho da chave) |
| Saída | Segredo compartilhado (bytes brutos) | Texto cifrado |
| Requer cifra simétrica? | Sim, sempre | Não (mas híbrido é recomendado) |
| Número de participantes | Exatamente 2 | 1 remetente, 1 destinatário |

Isso significa que o ECDH é sempre usado como **parte de um protocolo maior**: o ECDH produz o segredo compartilhado, uma KDF deriva uma chave a partir dele, e uma cifra simétrica (como AES-GCM) cifra os dados reais.

### 1.3 Fundamento Matemático

A segurança do ECDH se baseia no **Problema do Logaritmo Discreto de Curvas Elípticas (ECDLP)**. Uma curva elíptica sobre um corpo finito é definida por uma equação da forma:

```
y^2 = x^3 + ax + b  (mod p)
```

Em tal curva, uma operação especial chamada **multiplicação de pontos** é definida: dado um ponto base G e um escalar d, podemos calcular Q = d * G (somando G consigo mesmo d vezes usando a lei de grupo da curva). Esta operação é eficiente de calcular.

Porém, o **problema inverso** -- dado Q e G, encontrar d -- é computacionalmente inviável para curvas grandes. Este é o ECDLP. O melhor ataque conhecido é o **algoritmo rho de Pollard** com complexidade O(sqrt(n)), o que significa que uma curva de n bits fornece aproximadamente **n/2 bits de segurança**.

Para comparação, a segurança do RSA se baseia na fatoração de inteiros, onde existem ataques sub-exponenciais (crivo geral de corpo de números). Por isso a ECC alcança segurança equivalente com tamanhos de chave dramaticamente menores.

---

## 2. Como Funciona

O processo de acordo de chaves ECDH segue estes passos:

### Passo a Passo

1. **Ambas as partes concordam com os parâmetros da curva**: uma curva elíptica E definida sobre um corpo finito, e um ponto base G de ordem prima n. Estes parâmetros são públicos e padronizados (por exemplo, NIST P-256).

2. **A Parte A gera um par de chaves**:
   - Escolhe uma chave privada aleatória d_A no intervalo [1, n-1].
   - Calcula a chave pública Q_A = d_A * G.

3. **A Parte B gera um par de chaves**:
   - Escolhe uma chave privada aleatória d_B no intervalo [1, n-1].
   - Calcula a chave pública Q_B = d_B * G.

4. **Trocam chaves públicas**: Q_A e Q_B são enviadas através do canal (possivelmente inseguro). As chaves privadas d_A e d_B **nunca são transmitidas**.

5. **A Parte A calcula o segredo compartilhado**:
   - S = d_A * Q_B = d_A * (d_B * G)

6. **A Parte B calcula o segredo compartilhado**:
   - S = d_B * Q_A = d_B * (d_A * G)

7. **Ambas chegam ao mesmo ponto S**: porque a multiplicação escalar em curvas elípticas é associativa e comutativa, d_A * (d_B * G) = d_B * (d_A * G).

8. **O segredo compartilhado** e a coordenada x do ponto S.

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
    (mesmo ponto!)                      (mesmo ponto!)
```

Um espia que observe Q_A e Q_B não pode calcular S sem conhecer d_A ou d_B. Para isso, precisaria resolver o ECDLP, o que é computacionalmente inviável para curvas de tamanho adequado.

### Por Que é Seguro

A segurança vem do fato de que enquanto calcular Q = d * G é fácil (tempo polinomial), recuperar d a partir de Q e G é difícil (tempo exponencial para curvas adequadamente escolhidas). Um atacante que observe Q_A = d_A * G e Q_B = d_B * G não pode calcular eficientemente d_A * d_B * G sem conhecer pelo menos um dos escalares privados.

Isso é formalizado como a **suposição Computational Diffie-Hellman (CDH)** sobre curvas elípticas: dados G, d_A * G, e d_B * G, é inviável calcular d_A * d_B * G.

---

## 3. Curvas Recomendadas

O NIST padronizou várias curvas elípticas para uso criptográfico. A tabela a seguir compara as três curvas NIST principais:

| Curva | Tamanho do Campo | Nível de Segurança | Tamanho da Chave ECC | Chave RSA Equivalente | Proporção RSA:ECC |
|---|---|---|---|---|---|
| P-256 (secp256r1) | 256 bits | 128 bits | 256 bits | 3072 bits | 12:1 |
| P-384 (secp384r1) | 384 bits | 192 bits | 384 bits | 7680 bits | 20:1 |
| P-521 (secp521r1) | 521 bits | ~260 bits | 521 bits | 15360 bits | ~29:1 |

A observação chave aqui é que a ECC fornece **segurança equivalente com tamanhos de chave dramaticamente menores**. Com segurança de 128 bits, uma chave ECC é de 256 bits versus 3072 bits do RSA -- uma proporção de 12:1. Isso se traduz em cálculos mais rápidos, menos largura de banda e certificados menores.

### Como Escolher

- **P-256**: a curva mais utilizada. Fornece segurança de 128 bits, o que é considerado suficiente para a maioria das aplicações atuais e no futuro previsível. É a opção padrão para TLS 1.3, e se beneficia de aceleração por hardware em processadores modernos.

- **P-384**: fornece segurança de 192 bits. Usada quando regulamentações ou requisitos de conformidade exigem uma margem de segurança maior (por exemplo, certos sistemas governamentais ou financeiros).

- **P-521**: fornece aproximadamente 260 bits de segurança. Raramente necessária na prática -- a segurança de 128 bits já está além do alcance de força bruta. Porém, pode ser escolhida para margem de segurança máxima em chaves de longa duração.

> **Recomendação**: use **P-256** para uso geral. É a mais amplamente suportada, a mais eficiente, e fornece uma ampla margem de segurança.

### Uma Nota sobre Curve25519

Embora não seja uma curva NIST, a **Curve25519** (usada através da função de troca de chaves X25519) merece menção. Projetada por Daniel J. Bernstein, fornece aproximadamente 128 bits de segurança e é amplamente utilizada em protocolos modernos (TLS 1.3, Signal, WireGuard). Seu projeto prioriza a resistência a erros de implementação e ataques de canal lateral.

---

## 4. Por que Usar uma KDF (Função de Derivação de Chaves)?

O segredo compartilhado bruto produzido pelo ECDH **nunca** deve ser usado diretamente como chave criptográfica. Uma **Função de Derivação de Chaves (KDF)** deve sempre ser aplicada primeiro.

### Razões

1. **Distribuição não uniforme**: a coordenada x do ponto compartilhado é enviesada pela estrutura da curva. Não está uniformemente distribuída entre todas as cadeias de bits possíveis de seu comprimento, o que significa que usá-la diretamente como chave introduziria fraquezas sutis.

2. **Vinculação de contexto**: uma KDF pode vincular a chave derivada a informações de contexto específicas -- identificadores das partes, identificadores de algoritmos, nonces e dados de sessão. Isso evita que um atacante reutilize um segredo compartilhado em um contexto diferente.

3. **Separação de chaves**: a partir de um único segredo compartilhado, uma KDF pode derivar múltiplas chaves independentes para diferentes propósitos (por exemplo, uma chave para criptografia, outra para autenticação). Sem uma KDF, usar o mesmo segredo bruto para múltiplos propósitos criaria dependências cruzadas perigosas.

4. **Suporte a sigilo futuro**: quando usada com chaves efêmeras, cada sessão produz material de chaves independente. A KDF garante que as chaves derivadas sejam criptograficamente independentes mesmo se os segredos compartilhados estiverem relacionados.

### HKDF (RFC 5869)

**HKDF** (Função de Derivação de Chaves baseada em HMAC) é a KDF recomendada para uso com ECDH. Opera em duas fases:

1. **Extrair**: recebe o material de entrada de chaves não uniforme (IKM) e um sal opcional, e produz uma chave pseudoaleatória (PRK):
   ```
   PRK = HMAC-Hash(sal, IKM)
   ```
   O sal deve ser um valor aleatório ou pseudoaleatório. Se não estiver disponível, pode ser usada uma cadeia de zeros de comprimento igual à saída do hash.

2. **Expandir**: recebe o PRK e informações opcionais de contexto/aplicação (info), e produz o material de chaves de saída (OKM) do comprimento desejado:
   ```
   T(1) = HMAC-Hash(PRK, info || 0x01)
   T(2) = HMAC-Hash(PRK, T(1) || info || 0x02)
   OKM = primeiros L bytes de T(1) || T(2) || ...
   ```

**SHA-256** é a opção de hash padrão para HKDF. O parâmetro info deve incluir identificadores de ambas as partes e o uso pretendido da chave.

---

## 5. ECDH + Criptografia Simétrica

### 5.1 Combinação Recomendada com AES

O AES é a escolha natural para a etapa de criptografia simétrica porque é aprovado pelo NIST, se beneficia de aceleração por hardware (AES-NI), é extremamente rápido e é universalmente suportado em todas as plataformas e linguagens.

A tabela a seguir mostra a combinação recomendada entre curvas ECDH e tamanhos de chave AES, correspondendo seus níveis de segurança:

| Curva | AES Recomendado | Correspondência de Segurança |
|---|---|---|
| P-256 | AES-128 | 128 bits <-> 128 bits |
| P-384 | AES-192 ou AES-256 | 192 bits <-> 192/256 bits |
| P-521 | AES-256 | ~260 bits <-> 256 bits |

**AES-GCM** é o modo recomendado, pois fornece tanto confidencialidade quanto autenticação (AEAD -- Criptografia Autenticada com Dados Associados). Isso significa que não apenas cifra os dados, mas também produz uma etiqueta de autenticação que detecta qualquer adulteração.

### 5.2 Outros Algoritmos Simétricos

O ECDH não está limitado ao AES. O segredo compartilhado, uma vez processado através de uma KDF, produz bytes de chave brutos que podem ser usados com **qualquer** cifra simétrica. Outras opções incluem:

- **ChaCha20-Poly1305**: uma alternativa popular ao AES-GCM, amplamente usada no TLS 1.3. É particularmente eficiente em software em plataformas sem aceleração de hardware AES.
- **Camellia**: uma alternativa aprovada pelo NIST ao AES com uma estrutura de cifra de blocos similar.
- Qualquer outra cifra simétrica que aceite material de chaves do comprimento apropriado.

A escolha do algoritmo simétrico é **independente** do ECDH -- a KDF produz bytes de chave brutos que podem ser alimentados a qualquer cifra.

### 5.3 Fluxo Prático

O fluxo completo desde a troca de chaves até a comunicação cifrada:

```
1. Troca de Chaves (uma vez):
   App     -> gera (privA, pubA), envia pubA para o Backend
   Backend -> gera (privB, pubB), envia pubB para a App
   Ambos derivam: segredoCompartilhado = ECDH(minhaPrivada, publicaDeles)
   Ambos derivam: chaveAes = HKDF(segredoCompartilhado)

2. Comunicacao (cada mensagem):
   Remetente:    textoCifrado = AES-GCM(chaveAes, textoClaro)
   Destinatário: textoClaro   = AES-GCM(chaveAes, textoCifrado)
```

Este é o padrão de criptografia híbrida: o ECDH cuida do acordo de chaves (resolvendo o problema de distribuição de chaves), e o AES cuida da criptografia em massa dos dados (rápido, sem limites de tamanho).

---

## 6. Esquemas de Acordo de Chaves

O NIST SP 800-56A define vários esquemas de acordo de chaves baseados nos tipos de chaves usados por cada parte. A distinção é entre chaves **efêmeras** (geradas novas para cada sessão) e chaves **estáticas** (de longa duração, armazenadas de forma persistente).

| Esquema | Descrição | Sigilo Futuro |
|---|---|---|
| dhEphem (C(2e, 0s)) | Ambas as partes usam apenas chaves efêmeras | Sim |
| dhOneFlow (C(1e, 1s)) | Uma parte efêmera, uma estática | Parcial |
| dhStatic (C(0e, 2s)) | Ambas as partes usam chaves estáticas | Não |
| dhHybrid1 (C(2e, 2s)) | Combinação de chaves efêmeras e estáticas | Sim |

### Chaves Efêmeras vs Estáticas

- As **chaves efêmeras** são geradas novas para cada sessão e destruídas após calcular o segredo compartilhado. Elas fornecem **sigilo futuro**: se uma chave privada de longo prazo for comprometida no futuro, as sessões passadas permanecem seguras porque as chaves efêmeras já não existem.

- As **chaves estáticas** são de longa duração e reutilizadas entre sessões. São mais simples de gerenciar (não é necessário gerar novas chaves para cada sessão) mas **não** fornecem sigilo futuro: se a chave privada estática for comprometida, todas as sessões passadas que usaram essa chave podem ser decifradas.

### Escolhendo um Esquema

- **dhEphem (C(2e, 0s))**: ambas as partes geram pares de chaves novos para cada sessão. Esta é a opção mais forte e é usada no TLS 1.3. Porém, não fornece confirmação de chaves ou autenticação de identidade por si só -- estas devem vir de mecanismos adicionais (por exemplo, assinaturas digitais nas chaves públicas efêmeras).

- **dhOneFlow (C(1e, 1s))**: uma parte (tipicamente um servidor) tem uma chave estática, enquanto a outra (tipicamente um cliente) usa uma chave efêmera. Isso fornece sigilo futuro parcial -- se a chave estática do servidor for comprometida, as sessões passadas ficam expostas, mas se a chave efêmera do cliente estiver segura, a sessão atual está protegida.

- **dhStatic (C(0e, 2s))**: ambas as partes usam chaves estáticas. O segredo compartilhado é o mesmo para cada sessão entre as mesmas duas partes. Sem sigilo futuro. Útil apenas em ambientes restritos onde a geração de chaves por sessão é impraticável.

- **dhHybrid1 (C(2e, 2s))**: combina tanto chaves efêmeras quanto estáticas. O segredo compartilhado final incorpora ambas. Fornece sigilo futuro e também permite autenticação através das chaves estáticas.

---

## 7. Formatos de Chaves

### 7.1 Formatos de Chave Pública

| Formato | Descrição | Cabeçalho PEM |
|---|---|---|
| X.509 (SubjectPublicKeyInfo) | Formato padrão com identificador de algoritmo e OID da curva | `BEGIN PUBLIC KEY` |
| Ponto Não Comprimido | Bytes brutos: 0x04 || x || y | N/A (bytes brutos) |

#### X.509 (SubjectPublicKeyInfo)

Este é o formato padrão para chaves públicas EC, análogo ao formato X.509 usado para chaves públicas RSA. Ele envolve o ponto público bruto com um identificador de algoritmo que especifica tanto o tipo de chave (EC) quanto a curva.

Estrutura ASN.1:

```
SEQUENCE {
  SEQUENCE {                    -- AlgorithmIdentifier
    OID 1.2.840.10045.2.1      -- id-ecPublicKey
    OID <curve-oid>             -- namedCurve (ex., 1.2.840.10045.3.1.7 para P-256)
  }
  BIT STRING <0x04 || x || y>  -- ponto não comprimido
}
```

Codificação PEM:

```
-----BEGIN PUBLIC KEY-----
(Dados DER codificados em Base64)
-----END PUBLIC KEY-----
```

#### Formato de Ponto Não Comprimido

A chave pública bruta é representada como um único byte 0x04 (indicando formato não comprimido) seguido das coordenadas x e y do ponto, cada uma preenchida até o tamanho do campo:

```
04 || coordenada-x || coordenada-y
```

Para P-256, isso é 1 + 32 + 32 = 65 bytes. Para P-384, é 1 + 48 + 48 = 97 bytes. Para P-521, é 1 + 66 + 66 = 133 bytes.

### 7.2 Formatos de Chave Privada

| Formato | Descrição | Cabeçalho PEM |
|---|---|---|
| PKCS#8 (PrivateKeyInfo) | Formato genérico padrão com identificador de algoritmo | `BEGIN PRIVATE KEY` |
| SEC1 (RFC 5915) | Formato específico de EC com curva e chave pública opcionais | `BEGIN EC PRIVATE KEY` |

#### PKCS#8 (PrivateKeyInfo)

O formato genérico de chave privada, idêntico em conceito ao formato PKCS#8 usado para RSA. Ele envolve os dados de chave específicos de EC com um identificador de algoritmo.

```
-----BEGIN PRIVATE KEY-----
(Dados DER codificados em Base64)
-----END PRIVATE KEY-----
```

Vantagens:
- Agnóstico de algoritmo: o mesmo formato é usado para RSA, EC e outros tipos de chaves.
- Suporta criptografia da própria chave privada (EncryptedPrivateKeyInfo).
- Amplamente suportado em todas as plataformas e bibliotecas.

#### SEC1 (RFC 5915)

Um formato específico de EC que contém o escalar privado d e opcionalmente inclui os parâmetros da curva e a chave pública correspondente.

Estrutura ASN.1:

```
SEQUENCE {
  INTEGER 1                        -- versão
  OCTET STRING <chave-privada-d>   -- chave privada (preenchida até o tamanho do campo)
  [0] OID <curve-oid>              -- parâmetros (opcional)
  [1] BIT STRING <ponto-publico>   -- chavePública (opcional)
}
```

Codificação PEM:

```
-----BEGIN EC PRIVATE KEY-----
(Dados DER codificados em Base64)
-----END EC PRIVATE KEY-----
```

### Comparação de Formatos

| Formato | Tipo de Chave | Específico de EC? | Cabeçalho PEM |
|---|---|---|---|
| X.509 | Somente pública | Não (genérico) | `BEGIN PUBLIC KEY` |
| Ponto Não Comprimido | Somente pública | Sim | N/A (bytes brutos) |
| PKCS#8 | Somente privada | Não (genérico) | `BEGIN PRIVATE KEY` |
| SEC1 | Somente privada | Sim | `BEGIN EC PRIVATE KEY` |

---

## 8. Considerações de Segurança

1. **Sempre validar as chaves públicas** (obrigatório conforme NIST SP 800-56A Seção 5.6.2.3):
   - Verificar que o ponto não é o ponto no infinito.
   - Verificar que o ponto está na curva (satisfaz a equação da curva).
   - Verificar n * Q = O (o ponto está no subgrupo correto de ordem prima).
   - Não validar habilita **ataques de curva inválida**, onde um atacante envia um ponto cuidadosamente elaborado que se encontra em uma curva diferente (mais fraca), potencialmente permitindo a recuperação da chave privada.

2. **Sempre aplicar uma KDF**: nunca usar o segredo compartilhado bruto diretamente como chave criptográfica. A coordenada x do ponto compartilhado não está uniformemente distribuída e não possui vinculação de contexto (ver seção 4).

3. **Usar apenas curvas aprovadas**: P-256, P-384 e P-521 do NIST SP 800-186. Evitar curvas não padrão ou obsoletas.

4. **Usar um RNG criptograficamente seguro**: as chaves privadas devem ser geradas usando um gerador de números aleatórios em conformidade com NIST SP 800-90A. Aleatoriedade fraca compromete completamente a segurança do protocolo -- se um atacante puder prever ou reduzir o espaço de chaves privadas, o ECDLP se torna resolvível.

5. **Destruir as chaves privadas efêmeras**: após calcular o segredo compartilhado, as chaves privadas efêmeras devem ser destruídas imediatamente. Retê-las anula o benefício de sigilo futuro do acordo de chaves efêmero.

6. **Incluir contexto na KDF**: vincular as chaves derivadas ao contexto do protocolo através do parâmetro info do HKDF. Isso deve incluir identificadores das partes, identificadores de algoritmos e dados específicos de sessão para prevenir ataques entre protocolos.

7. **Verificar a saída zero**: verificar que o segredo compartilhado não é o ponto no infinito (coordenada x toda zerada). Um segredo compartilhado zero indica um **ataque de subgrupo pequeno** e a troca de chaves deve ser abortada.

8. **Igualar níveis de segurança**: usar níveis de segurança consistentes em todos os componentes. Não combinar P-256 (segurança de 128 bits) com AES-256 (segurança de 256 bits) -- a segurança geral é limitada pelo elo mais fraco. P-256 deve ser combinada com AES-128, P-384 com AES-192 ou AES-256, e P-521 com AES-256.

---

## 9. Casos de Uso

O ECDH (e sua variante efêmera ECDHE) é usado em virtualmente todos os protocolos de segurança modernos:

- **TLS 1.3** (RFC 8446): ECDHE é obrigatório para a troca de chaves. O transporte de chaves RSA estático foi removido completamente no TLS 1.3. Os grupos suportados incluem x25519, secp256r1, secp384r1 e secp521r1.

- **Protocolo Signal**: usa X25519 (Diffie-Hellman baseado em Curve25519) para X3DH (Extended Triple Diffie-Hellman) como acordo de chaves inicial e para o Double Ratchet DH contínuo que fornece sigilo futuro para cada mensagem.

- **WireGuard VPN**: usa X25519 para seu padrão de handshake Noise_IKpsk2, estabelecendo um túnel seguro com mínimas idas e vindas.

- **SSH** (RFC 5656, RFC 8731): troca de chaves ECDH com curvas NIST (ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521) e curve25519 (curve25519-sha256).

- **ECIES** (Esquema de Criptografia Integrado de Curvas Elípticas): combina ECDH + KDF + criptografia simétrica + MAC em um esquema de criptografia híbrido completo. Definido na SEC 1 Seção 5.1. É útil quando uma parte tem uma chave pública estática e a outra quer cifrar uma mensagem para ela sem interação prévia.

- **Cofres de senhas e aplicativos seguros**: comunicação bidirecional entre um aplicativo móvel e um backend usando ECDH para acordo de chaves combinado com AES para criptografia de dados. O app e o backend trocam chaves públicas uma vez, derivam uma chave simétrica compartilhada, e então cifram toda a comunicação subsequente com AES-GCM.

---

## 10. Referências

### Padrões NIST

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

### Padrões da Indústria

- [**SEC 1 v2**](https://www.secg.org/sec1-v2.pdf) -- Elliptic Curve Cryptography. SECG, 2009.
- [**SEC 2 v2**](https://www.secg.org/sec2-v2.pdf) -- Recommended Elliptic Curve Domain Parameters. SECG, 2010.
