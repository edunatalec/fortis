# AES (Advanced Encryption Standard)

O AES é o algoritmo de criptografia simétrica mais utilizado no mundo. Ele é um padrão do governo dos Estados Unidos e é adotado globalmente em praticamente todos os protocolos e sistemas de segurança modernos.

## Sumário

- [1. O que é AES?](#1-o-que-é-aes)
- [2. História](#2-história)
- [3. Como Funciona](#3-como-funciona)
- [4. Tamanhos de Chave](#4-tamanhos-de-chave)
- [5. Modos de Operação](#5-modos-de-operação)
  - [5.1 ECB (Electronic Codebook)](#51-ecb-electronic-codebook)
  - [5.2 CBC (Cipher Block Chaining)](#52-cbc-cipher-block-chaining)
  - [5.3 CTR (Counter)](#53-ctr-counter)
  - [5.4 GCM (Galois/Counter Mode)](#54-gcm-galoiscounter-mode)
  - [5.5 CFB (Cipher Feedback)](#55-cfb-cipher-feedback)
  - [5.6 OFB (Output Feedback)](#56-ofb-output-feedback)
  - [5.7 CCM (Counter with CBC-MAC)](#57-ccm-counter-with-cbc-mac)
- [6. Comparação dos Modos de Operação](#6-comparação-dos-modos-de-operação)
- [7. Padding (Preenchimento)](#7-padding-preenchimento)
  - [7.1 PKCS#7](#71-pkcs7)
  - [7.2 ISO 7816-4](#72-iso-7816-4)
  - [7.3 Zero Padding](#73-zero-padding)
  - [7.4 Sem Padding (No Padding)](#74-sem-padding-no-padding)
- [8. Considerações de Segurança](#8-considerações-de-segurança)
- [9. Referências](#9-referências)

---

## 1. O que é AES?

O AES (*Advanced Encryption Standard*) é o algoritmo de criptografia simétrica mais utilizado no mundo. Ele é um padrão do governo dos Estados Unidos, oficialmente publicado como **FIPS 197** pelo NIST, e é adotado globalmente em praticamente todos os protocolos e sistemas de segurança modernos — incluindo TLS 1.3, SSH, IPsec, Wi-Fi WPA2, criptografia de disco (BitLocker, FileVault, LUKS) e muitos outros.

O AES é uma **cifra de bloco** (*block cipher*): ele opera sobre blocos de dados de tamanho fixo de **128 bits (16 bytes)**, usando chaves de **128**, **192** ou **256 bits**. Foi projetado para ser eficiente tanto em software quanto em hardware, e permanece seguro contra todos os ataques práticos conhecidos.

---

## 2. História

Na década de 1990, o **DES** (*Data Encryption Standard*), que havia sido o padrão desde 1977, estava claramente envelhecendo. Com uma chave de apenas 56 bits, ele já podia ser quebrado por força bruta — em 1999, uma máquina dedicada quebrou o DES em menos de 24 horas.

Em **janeiro de 1997**, o NIST (*National Institute of Standards and Technology*) lançou uma chamada pública internacional para propor um novo padrão de criptografia. O processo foi aberto e transparente:

- **15 algoritmos** foram submetidos por equipes de todo o mundo.
- **5 finalistas** foram selecionados: Rijndael, Serpent, Twofish, RC6 e MARS.
- Em **outubro de 2000**, o NIST anunciou o vencedor: **Rijndael**.

O Rijndael foi desenvolvido por dois criptógrafos belgas, **Joan Daemen** e **Vincent Rijmen**, do laboratório ESAT/COSIC da Universidade KU Leuven, na Bélgica. A escolha surpreendeu muitos observadores, que não esperavam que o governo americano adotasse um padrão criado por não-americanos — o que demonstrou a seriedade e imparcialidade do processo de seleção.

Em **26 de novembro de 2001**, o AES foi oficialmente publicado como **FIPS 197** pelo NIST.

---

## 3. Como Funciona

O AES é uma **cifra de bloco** (*block cipher*): ele opera sobre blocos de dados de tamanho fixo de **128 bits (16 bytes)**. Se os dados a serem cifrados forem maiores que 128 bits, é necessário um **modo de operação** (seção 5) para processar múltiplos blocos.

Internamente, o AES utiliza uma **rede de substituição-permutação** (*substitution-permutation network* — SPN). Os dados passam por múltiplas rodadas (*rounds*) de transformação, onde cada rodada aplica quatro operações:

1. **SubBytes** — Cada byte do bloco é substituído por outro usando uma tabela de substituição (S-box). Essa etapa introduz **não-linearidade**, essencial para a segurança.

2. **ShiftRows** — As linhas da matriz de estado (4×4 bytes) são deslocadas ciclicamente. A primeira linha não muda, a segunda é deslocada 1 posição, a terceira 2 posições e a quarta 3 posições. Isso garante **difusão** entre as colunas.

3. **MixColumns** — Cada coluna da matriz é transformada por uma multiplicação de matrizes no campo GF(2⁸). Isso proporciona **difusão** adicional, fazendo com que cada byte de saída dependa de todos os bytes da coluna de entrada. (Esta etapa é omitida na última rodada.)

4. **AddRoundKey** — O bloco é combinado (XOR) com uma subchave derivada da chave principal. Sem essa etapa, as operações anteriores seriam apenas uma substituição fixa que poderia ser pré-computada.

---

## 4. Tamanhos de Chave

O AES suporta três tamanhos de chave. A diferença principal é o número de rodadas de transformação:

| Tamanho da Chave | Número de Rounds | Nível de Segurança |
|---|---|---|
| 128 bits (16 bytes) | 10 | Seguro para uso geral |
| 192 bits (24 bytes) | 12 | Margem de segurança adicional |
| 256 bits (32 bytes) | 14 | Máximo — exigido para dados classificados pelo governo dos EUA |

Todos os três tamanhos são considerados seguros atualmente. O **AES-128** é suficiente para a grande maioria dos casos de uso. O **AES-256** é recomendado quando se deseja uma margem de segurança extra contra possíveis avanços futuros (incluindo computação quântica, onde o algoritmo de Grover reduziria efetivamente a segurança do AES-256 para ~128 bits simétricos).

---

## 5. Modos de Operação

Como o AES opera em blocos de 128 bits, é necessário um **modo de operação** para cifrar dados maiores que um único bloco. Cada modo define como os blocos são processados e encadeados, e cada um tem propriedades de segurança e desempenho distintas.

### 5.1 ECB (Electronic Codebook)

**Referência**: NIST SP 800-38A

Cada bloco é cifrado **independentemente** com a mesma chave. Não utiliza IV (*Initialization Vector*).

```
Bloco 1 → AES(chave) → Bloco cifrado 1
Bloco 2 → AES(chave) → Bloco cifrado 2
Bloco 3 → AES(chave) → Bloco cifrado 3
```

**INSEGURO para a maioria dos usos.** O principal problema é que blocos de texto claro idênticos produzem blocos cifrados idênticos, o que vaza padrões dos dados originais. O exemplo clássico é o "pinguim ECB": ao cifrar uma imagem com ECB, a silhueta da imagem original permanece claramente visível no resultado cifrado.

O ECB só é aceitável em cenários muito específicos, como cifrar um único bloco de dados (por exemplo, uma única chave AES).

### 5.2 CBC (Cipher Block Chaining)

**Referência**: NIST SP 800-38A

Cada bloco de texto claro é combinado (XOR) com o **bloco cifrado anterior** antes de ser cifrado. O primeiro bloco usa um **IV** (*Initialization Vector*) de 16 bytes.

```
Bloco cifrado 1 = AES(chave, IV ⊕ Bloco 1)
Bloco cifrado 2 = AES(chave, Bloco cifrado 1 ⊕ Bloco 2)
Bloco cifrado 3 = AES(chave, Bloco cifrado 2 ⊕ Bloco 3)
```

**Características:**

- O IV deve ser **aleatório e imprevisível** para cada operação de cifragem.
- A cifragem é **sequencial** (não pode ser paralelizada).
- A decifragem **pode** ser paralelizada.
- Requer **padding** (pois os dados precisam ser múltiplo do tamanho do bloco).
- Vulnerável a **ataques de padding oracle** se não combinado com autenticação (MAC).

### 5.3 CTR (Counter)

**Referência**: NIST SP 800-38A

Transforma a cifra de bloco em uma **cifra de fluxo** (*stream cipher*). Um **nonce** concatenado com um **contador** sequencial é cifrado, e o resultado é combinado (XOR) com o texto claro.

```
Keystream 1 = AES(chave, nonce || contador_1)    →  Cifrado 1 = Keystream 1 ⊕ Bloco 1
Keystream 2 = AES(chave, nonce || contador_2)    →  Cifrado 2 = Keystream 2 ⊕ Bloco 2
```

**Características:**

- Totalmente **paralelizável** (tanto cifragem quanto decifragem).
- **Não requer padding** — opera byte a byte.
- O **nonce nunca deve ser reutilizado** com a mesma chave. A reutilização compromete completamente a segurança.
- Não fornece autenticação — apenas confidencialidade.

### 5.4 GCM (Galois/Counter Mode)

**Referência**: NIST SP 800-38D (2007)

O GCM combina o modo **CTR** (para confidencialidade) com a autenticação **GHASH** (baseada em multiplicação no campo de Galois). É um modo **AEAD** (*Authenticated Encryption with Associated Data*), o que significa que ele fornece **confidencialidade e autenticidade** simultaneamente.

**Características:**

- Produz uma **tag de autenticação** (tipicamente 128 bits) que permite verificar se os dados foram adulterados.
- Suporta **AAD** (*Additional Authenticated Data*): dados que são autenticados mas não cifrados (como cabeçalhos de protocolo).
- O nonce/IV recomendado é de **96 bits (12 bytes)** — comprimentos diferentes são suportados mas reduzem a segurança.
- Totalmente **paralelizável**.
- O **nonce nunca deve ser reutilizado** com a mesma chave. A reutilização no GCM é catastrófica: permite recuperar a chave de autenticação e forjar mensagens.

O GCM é o **modo recomendado para a maioria das aplicações** modernas. Ele é usado no TLS 1.3, SSH, IPsec e muitos outros protocolos.

### 5.5 CFB (Cipher Feedback)

**Referência**: NIST SP 800-38A

Transforma a cifra de bloco em uma **cifra de fluxo auto-sincronizante**. O bloco cifrado anterior (ou o IV, no caso do primeiro bloco) é cifrado, e o resultado é combinado (XOR) com o texto claro.

```
Keystream 1 = AES(chave, IV)                →  Cifrado 1 = Keystream 1 ⊕ Bloco 1
Keystream 2 = AES(chave, Cifrado 1)         →  Cifrado 2 = Keystream 2 ⊕ Bloco 2
```

**Características:**

- A cifragem é **sequencial**.
- A decifragem **pode** ser paralelizada.
- Requer um **IV** de 16 bytes.
- Não requer padding.
- Erros de bit no texto cifrado afetam o bloco atual e o próximo, depois se auto-corrigem.

### 5.6 OFB (Output Feedback)

**Referência**: NIST SP 800-38A

Gera uma **keystream independente** do texto claro e do texto cifrado. O resultado da cifragem do IV (ou do keystream anterior) é usado como entrada para o próximo passo, e a keystream é combinada (XOR) com o texto claro.

```
Keystream 1 = AES(chave, IV)              →  Cifrado 1 = Keystream 1 ⊕ Bloco 1
Keystream 2 = AES(chave, Keystream 1)     →  Cifrado 2 = Keystream 2 ⊕ Bloco 2
```

**Características:**

- Cifragem e decifragem são **idênticas** (mesma operação XOR).
- **Não paralelizável** (nem cifragem nem decifragem).
- **Erros de bit não propagam** — um bit corrompido no texto cifrado afeta apenas o bit correspondente no texto claro.
- O **IV nunca deve ser reutilizado** com a mesma chave.
- Não requer padding.

### 5.7 CCM (Counter with CBC-MAC)

**Referência**: NIST SP 800-38C, RFC 3610

O CCM combina o modo **CTR** (para confidencialidade) com **CBC-MAC** (para autenticação). Assim como o GCM, é um modo **AEAD**.

**Características:**

- Requer **dois passes** sobre os dados (um para o MAC, outro para a cifragem), ao contrário do GCM que faz em um único passe.
- O nonce tem tamanho entre **7 e 13 bytes** (padrão: 11 bytes). Existe uma relação inversa: L + N = 15, onde L é o campo que define o tamanho máximo da mensagem e N é o tamanho do nonce.
- Suporta AAD.
- Amplamente usado em **IEEE 802.11i (Wi-Fi WPA2)** e **Bluetooth**.
- Menos eficiente que o GCM, mas pode ser preferido em ambientes com restrições de hardware.

---

## 6. Comparação dos Modos de Operação

| Modo | Confidencialidade | Autenticação | Paralelizável (Cifrar) | Paralelizável (Decifrar) | IV/Nonce | Padding |
|---|---|---|---|---|---|---|
| ECB | Sim | Não | Sim | Sim | Não usa | Sim |
| CBC | Sim | Não | Não | Sim | 16 bytes (aleatório) | Sim |
| CTR | Sim | Não | Sim | Sim | Nonce (único) | Não |
| **GCM** | **Sim** | **Sim** | **Sim** | **Sim** | **12 bytes (recomendado)** | **Não** |
| CFB | Sim | Não | Não | Sim | 16 bytes | Não |
| OFB | Sim | Não | Não | Não | 16 bytes (único) | Não |
| **CCM** | **Sim** | **Sim** | **Sim** | **Sim** | **7-13 bytes** | **Não** |

> **Recomendação**: para a maioria dos cenários, use **GCM**. Ele fornece confidencialidade e autenticação, é paralelizável e é o modo padrão nos protocolos modernos. Use **CCM** quando estiver trabalhando com hardware restrito ou protocolos que o exigem (como WPA2).

---

## 7. Padding (Preenchimento)

O padding é necessário apenas para **modos de bloco** (ECB e CBC), onde o texto claro precisa ser um múltiplo exato de 16 bytes (128 bits). Modos de fluxo (CTR, CFB, OFB) e modos autenticados (GCM, CCM) não precisam de padding.

### 7.1 PKCS#7

**Referência**: RFC 5652

O esquema de padding mais utilizado e recomendado. Preenche com N bytes, cada um com o valor N (onde N é a quantidade de bytes necessários para completar o bloco).

```
Dados:    [0x48 0x65 0x6C 0x6C 0x6F]              (5 bytes — "Hello")
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B]
                                                    (11 bytes de padding, cada um = 0x0B)
```

Se os dados já forem múltiplo de 16, um **bloco inteiro de padding é adicionado** (16 bytes de valor 0x10). Isso garante que o padding é sempre **inequivocamente reversível**.

### 7.2 ISO 7816-4

**Referência**: ISO/IEC 7816-4

Também chamado de *bit padding*. Preenche com o byte `0x80` seguido de bytes `0x00` até completar o bloco.

```
Dados:    [0x48 0x65 0x6C 0x6C 0x6F]
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x80 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
```

Originalmente usado em aplicações de **smart cards**. Também é inequivocamente reversível, já que o marcador `0x80` indica onde o padding começa.

### 7.3 Zero Padding

Preenche com bytes `0x00` até completar o bloco.

```
Dados:    [0x48 0x65 0x6C 0x6C 0x6F]
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
```

**Problema**: se o texto claro terminar com bytes `0x00`, é impossível distinguir os bytes reais dos bytes de padding. Isso torna o zero padding **ambíguo para dados binários** e não recomendado para uso geral. Pode ser aceitável quando se sabe que os dados são exclusivamente texto.

### 7.4 Sem Padding (No Padding)

Nenhum preenchimento é adicionado. O texto claro **deve** ter tamanho exato múltiplo de 16 bytes. Caso contrário, a operação falhará.

Usado com modos de fluxo (CTR, CFB, OFB) e modos autenticados (GCM, CCM), que operam em nível de byte e não exigem alinhamento de bloco.

### Comparação dos Esquemas de Padding

| Esquema | Reversível sem Ambiguidade | Quando Usar |
|---|---|---|
| PKCS#7 | Sim | **Recomendado** para ECB e CBC |
| ISO 7816-4 | Sim | Smart cards ou quando exigido por padrão |
| Zero Padding | Não (dados binários) | Apenas texto — uso legado |
| Sem Padding | N/A | CTR, GCM, CFB, OFB, CCM |

---

## 8. Considerações de Segurança

- **Nunca reutilize nonce/IV com a mesma chave.** No CTR e GCM, a reutilização é catastrófica. No CBC, compromete a confidencialidade dos blocos iniciais.
- **Sempre prefira modos autenticados** (GCM ou CCM). Sem autenticação, um atacante pode alterar o texto cifrado de formas que produzem alterações previsíveis no texto claro.
- **Nunca use ECB** para dados maiores que um bloco, pois ele vaza padrões.
- **Derivação de chaves**: nunca use uma senha diretamente como chave AES. Use funções de derivação de chaves como PBKDF2, HKDF ou Argon2 para transformar uma senha em uma chave criptográfica adequada.
- **Geração de IV/nonce**: use sempre um gerador de números aleatórios criptograficamente seguro (CSPRNG).

---

## 9. Referências

### Padrões NIST (FIPS)

- [**FIPS 197**](https://csrc.nist.gov/pubs/fips/197/final) — Advanced Encryption Standard (AES). NIST, 2001 (atualizado 2023).

### Publicações Especiais NIST (SP)

- [**NIST SP 800-38A**](https://csrc.nist.gov/pubs/sp/800/38/a/final) — Recommendation for Block Cipher Modes of Operation: Methods and Techniques (ECB, CBC, CFB, OFB, CTR). NIST, 2001.
- [**NIST SP 800-38C**](https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final) — Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality. NIST, 2004.
- [**NIST SP 800-38D**](https://csrc.nist.gov/pubs/sp/800/38/d/final) — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC. NIST, 2007.

### RFCs (IETF)

- [**RFC 5652**](https://datatracker.ietf.org/doc/html/rfc5652) — Cryptographic Message Syntax (CMS). IETF, 2009.
- [**RFC 3610**](https://datatracker.ietf.org/doc/html/rfc3610) — Counter with CBC-MAC (CCM). IETF, 2003.
