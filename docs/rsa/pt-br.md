# RSA (Rivest-Shamir-Adleman)

## Sumário

- [1. O que é RSA?](#1-o-que-é-rsa)
- [2. História](#2-história)
- [3. Como Funciona](#3-como-funciona)
- [4. Tamanhos de Chave](#4-tamanhos-de-chave)
- [5. Esquemas de Padding](#5-esquemas-de-padding)
- [6. Algoritmos de Hash Usados com RSA](#6-algoritmos-de-hash-usados-com-rsa)
- [7. Formatos de Chave](#7-formatos-de-chave)
- [8. Considerações de Segurança](#8-considerações-de-segurança)
- [9. Referências](#9-referências)

---

## 1. O que é RSA?

O RSA é o algoritmo de criptografia assimétrica mais conhecido e utilizado. Ele pode ser usado tanto para **cifragem** quanto para **assinaturas digitais**.

---

## 2. História

Em **1977**, três pesquisadores do MIT — **Ron Rivest**, **Adi Shamir** e **Leonard Adleman** — publicaram o primeiro criptossistema de chave pública prático. Rivest e Shamir, ambos cientistas da computação, propunham funções candidatas, enquanto Adleman, matemático, tentava quebrá-las. Após 42 tentativas fracassadas, em abril de 1977, Rivest formalizou a ideia que se tornaria o RSA.

O algoritmo foi publicado na revista **Scientific American** em 1977 e rapidamente se tornou o padrão para criptografia de chave pública. A patente americana do RSA expirou em **setembro de 2000**, tornando-o livre para uso em todo o mundo.

O nome "RSA" vem das iniciais dos sobrenomes dos três criadores: **R**ivest, **S**hamir e **A**dleman.

---

## 3. Como Funciona

A segurança do RSA é baseada em um problema matemático: a **dificuldade de fatorar o produto de dois números primos muito grandes**. Multiplicar dois primos é rápido, mas dado apenas o resultado, encontrar os fatores originais é computacionalmente inviável para números suficientemente grandes.

### Geração de Chaves

1. Escolhem-se dois números primos grandes **p** e **q** (cada um com centenas de dígitos).
2. Calcula-se **n = p × q** (o módulo). Este valor é público.
3. Calcula-se **φ(n) = (p − 1) × (q − 1)** (a função totiente de Euler).
4. Escolhe-se um expoente público **e**, coprimo a φ(n). O valor mais utilizado é **e = 65537** (0x10001), escolhido por ser primo e ter poucos bits ativos (eficiente para exponenciação).
5. Calcula-se o expoente privado **d = e⁻¹ mod φ(n)** (o inverso modular de e).

- **Chave pública**: (n, e)
- **Chave privada**: (n, d)

### Cifragem e Decifragem

- **Cifrar**: c = m^e mod n (onde m é a mensagem numérica e c é o texto cifrado)
- **Decifrar**: m = c^d mod n

A segurança depende do fato de que, sem conhecer p e q (que compõem d), é computacionalmente inviável calcular d a partir de apenas (n, e).

---

## 4. Tamanhos de Chave

O tamanho da chave RSA (em bits) refere-se ao tamanho do módulo **n**. Chaves maiores oferecem mais segurança, mas são mais lentas.

A tabela abaixo mostra a equivalência entre o tamanho da chave RSA e a segurança equivalente em bits simétricos, conforme o **NIST SP 800-57 Part 1 Rev. 5**:

| Tamanho da Chave RSA | Segurança Equivalente (bits simétricos) | Status |
|---|---|---|
| 1024 bits | ~80 bits | **Obsoleto** — não usar |
| 2048 bits | ~112 bits | Mínimo recomendado atualmente |
| 3072 bits | ~128 bits | Boa margem de segurança |
| 4096 bits | ~140 bits | Alta segurança |
| 7680 bits | ~192 bits | Muito alta segurança |
| 15360 bits | ~256 bits | Máxima segurança (raro na prática) |

> **Recomendação**: use no mínimo **2048 bits**. Para segurança de longo prazo, prefira **4096 bits**. Note que a geração de chaves de 4096 bits pode ser significativamente mais lenta.

O tamanho da chave também limita o **tamanho máximo dos dados** que podem ser cifrados diretamente (detalhado na seção 5).

---

## 5. Esquemas de Padding

No RSA, a mensagem em texto claro precisa ser transformada em um número entre 0 e n−1 antes da cifragem. O **padding** (ou esquema de codificação) é o processo que faz essa transformação de forma segura. Cifrar sem padding (chamado "textbook RSA") é extremamente inseguro.

### 5.1 PKCS#1 v1.5

**Referência**: RFC 8017 (consolidação), originalmente RFC 2313

O esquema mais antigo e ainda amplamente encontrado. O formato da mensagem codificada é:

```
0x00 || 0x02 || PS || 0x00 || M
```

Onde:
- `PS` é um preenchimento de bytes **aleatórios não-zero** com no mínimo 8 bytes.
- `M` é a mensagem original.

O tamanho máximo da mensagem é: **mLen ≤ k − 11** bytes (onde k é o tamanho da chave em bytes).

**Vulnerabilidade**: em 1998, Daniel Bleichenbacher demonstrou um ataque (*Bleichenbacher's attack*, também chamado de "million message attack") que explora servidores que revelam se o padding de uma mensagem decifrada é válido ou não. Esse tipo de *padding oracle* permite que um atacante decifre mensagens sem a chave privada, enviando milhões de textos cifrados modificados e observando as respostas do servidor. Variantes desse ataque continuaram a ser exploráveis em 2018 (ROBOT) e 2023 (Marvin Attack).

**O PKCS#1 v1.5 é mantido apenas por compatibilidade com sistemas legados. Não deve ser usado em novos projetos.**

### 5.2 OAEP (Optimal Asymmetric Encryption Padding)

O OAEP foi proposto por **Bellare e Rogaway** em 1994 como uma alternativa provadamente segura ao PKCS#1 v1.5. Ele utiliza uma estrutura semelhante a uma **rede Feistel de duas rodadas** combinada com funções hash e uma **MGF** (*Mask Generation Function*).

O processo de codificação EME-OAEP (conforme RFC 8017) funciona assim:

1. Gera-se o hash do **label** L (por padrão, uma string vazia) para obter `lHash`.
2. Cria-se o bloco de dados: `DB = lHash || PS || 0x01 || M` (onde PS são bytes zero de preenchimento).
3. Gera-se um **seed aleatório** de comprimento igual ao hash.
4. Calcula-se `dbMask = MGF1(seed, comprimento_de_DB)`.
5. Calcula-se `maskedDB = DB ⊕ dbMask`.
6. Calcula-se `seedMask = MGF1(maskedDB, comprimento_do_hash)`.
7. Calcula-se `maskedSeed = seed ⊕ seedMask`.
8. A mensagem codificada final é: `EM = 0x00 || maskedSeed || maskedDB`.

O tamanho máximo da mensagem é: **mLen ≤ k − 2·hLen − 2** bytes (onde hLen é o tamanho da saída do hash em bytes).

### Versões do OAEP

| Versão | Referência | Detalhes |
|---|---|---|
| OAEP v1 | Bellare-Rogaway (1994) | Proposta original com SHA-1 |
| OAEP v2.0 | PKCS#1 v2.0 (RFC 2437) | Incorporação ao padrão PKCS#1 com MGF1 |
| OAEP v2.1 | PKCS#1 v2.1 (RFC 3447) / v2.2 (RFC 8017) | **Recomendado** — hash configurável, MGF1, suporte a label |

> **Recomendação**: use sempre **OAEP v2.1** (ou posterior) com **SHA-256** ou superior. Conforme a RFC 8017: *"RSAES-OAEP is required to be supported for new applications"*.

---

## 6. Algoritmos de Hash Usados com RSA

Funções hash são usadas no RSA em vários contextos:

- **Padding OAEP**: a função hash é usada para gerar `lHash` e como base da MGF1.
- **Assinaturas digitais**: a mensagem é hashada antes de ser assinada (*hash-then-sign*).
- **Fingerprints de chaves**: identificação resumida de chaves públicas.

A escolha do hash afeta diretamente o **tamanho máximo da mensagem** no OAEP (pois `hLen` entra na fórmula `k − 2·hLen − 2`).

| Algoritmo | Tamanho da Saída (hLen) | Status com RSA | Mensagem Máxima (RSA-2048) |
|---|---|---|---|
| SHA-1 | 20 bytes | Legado — evitar | 214 bytes |
| SHA-224 | 28 bytes | Válido, pouco usado | 198 bytes |
| SHA-256 | 32 bytes | **Recomendado** (padrão) | 190 bytes |
| SHA-384 | 48 bytes | Alta segurança | 158 bytes |
| SHA-512 | 64 bytes | Alta segurança | 126 bytes |
| SHA3-256 | 32 bytes | Alternativa moderna | 190 bytes |
| SHA3-512 | 64 bytes | Alternativa moderna | 126 bytes |

> **Nota**: a coluna "Mensagem Máxima" assume RSA-2048 (k = 256 bytes) e OAEP. Fórmula: k − 2·hLen − 2.

---

## 7. Formatos de Chave

Chaves RSA podem ser armazenadas e transmitidas em diferentes formatos padronizados. Cada formato tem um propósito específico.

### 7.1 PKCS#1

Formato **específico para RSA**. Contém apenas os parâmetros matemáticos do RSA.

- **Chave pública**: contém (n, e).
- **Chave privada**: contém (n, e, d, p, q, dP, dQ, qInv).
- Codificação: ASN.1 DER, tipicamente envolvida em PEM.

```
-----BEGIN RSA PUBLIC KEY-----
(dados codificados em Base64)
-----END RSA PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
(dados codificados em Base64)
-----END RSA PRIVATE KEY-----
```

### 7.2 PKCS#8 (PrivateKeyInfo)

**Referência**: RFC 5958

Formato **genérico** (não específico para RSA) para chaves privadas. Encapsula a chave com um identificador de algoritmo, o que permite distinguir chaves de diferentes algoritmos.

```
-----BEGIN PRIVATE KEY-----
(dados codificados em Base64)
-----END PRIVATE KEY-----
```

Vantagens:
- Suporta criptografia da chave privada em si (`EncryptedPrivateKeyInfo`).
- Portabilidade entre diferentes algoritmos.

### 7.3 X.509 (SubjectPublicKeyInfo)

**Referência**: RFC 5280

Formato **genérico** para chaves públicas, amplamente usado em certificados digitais. Encapsula a chave pública com um identificador de algoritmo.

```
-----BEGIN PUBLIC KEY-----
(dados codificados em Base64)
-----END PUBLIC KEY-----
```

### Comparação dos Formatos

| Formato | Tipo de Chave | Específico para RSA? | PEM Header |
|---|---|---|---|
| PKCS#1 | Pública e Privada | Sim | `BEGIN RSA PUBLIC KEY` / `BEGIN RSA PRIVATE KEY` |
| PKCS#8 | Apenas Privada | Não (genérico) | `BEGIN PRIVATE KEY` |
| X.509 | Apenas Pública | Não (genérico) | `BEGIN PUBLIC KEY` |

---

## 8. Considerações de Segurança

- **Tamanho mínimo de chave**: use no mínimo **2048 bits**. Chaves de 1024 bits são consideradas obsoletas.
- **Sempre use OAEP**: evite PKCS#1 v1.5 para cifragem em novos projetos devido à vulnerabilidade Bleichenbacher.
- **Não cifre dados grandes diretamente**: o RSA é limitado pelo tamanho da chave. Para dados maiores, use criptografia híbrida.
- **Geração de primos**: a qualidade do gerador de números aleatórios é crítica. Primos previsíveis comprometem completamente a segurança.
- **Ameaça quântica**: o **algoritmo de Shor** permite que um computador quântico suficientemente grande fatore números inteiros em tempo polinomial, o que quebraria o RSA. Embora computadores quânticos dessa capacidade ainda não existam, organizações sensíveis já estão planejando a migração para algoritmos pós-quânticos (como os selecionados pelo NIST: CRYSTALS-Kyber para cifragem e CRYSTALS-Dilithium para assinaturas).

---

## 9. Referências

- [RFC 8017 — PKCS#1 v2.2](https://datatracker.ietf.org/doc/html/rfc8017)
- [RFC 3447 — PKCS#1 v2.1](https://datatracker.ietf.org/doc/html/rfc3447)
- [RFC 2437 — PKCS#1 v2.0](https://datatracker.ietf.org/doc/html/rfc2437)
- [RFC 5958 — PKCS#8](https://datatracker.ietf.org/doc/html/rfc5958)
- [RFC 5280 — X.509](https://datatracker.ietf.org/doc/html/rfc5280)
- [NIST SP 800-57 — Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
