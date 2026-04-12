# Criptografia

Um guia completo sobre criptografia, abordando desde conceitos fundamentais até detalhes técnicos dos principais algoritmos criptográficos.

## Sumário

- [1. O que é Criptografia](#1-o-que-é-criptografia)
- [2. Criptografia Simétrica vs Assimétrica](#2-criptografia-simétrica-vs-assimétrica)
- [3. Funções Hash](#3-funções-hash)
- [4. AES (Advanced Encryption Standard)](#4-aes-advanced-encryption-standard)
- [5. RSA (Rivest-Shamir-Adleman)](#5-rsa-rivest-shamir-adleman)
- [6. Quando Usar AES vs RSA](#6-quando-usar-aes-vs-rsa)
- [7. Referências](#7-referências)

---

## 1. O que é Criptografia

### 1.1 Definição

A palavra **criptografia** vem do grego: *kryptós* (escondido, secreto) e *gráphein* (escrita). Em termos simples, criptografia é a ciência de transformar informações legíveis em algo incompreensível, de modo que apenas quem possui a "chave" correta consiga reverter o processo e ler a informação original.

Pense em um cofre: qualquer pessoa pode ver o cofre, mas somente quem tem a chave (ou a combinação) consegue abrir e acessar o que está dentro. A criptografia funciona da mesma forma — ela "tranca" seus dados para que apenas destinatários autorizados possam "destrancar" e lê-los.

### 1.2 Por que a Criptografia é Importante

A criptografia sustenta quatro pilares fundamentais da segurança da informação:

- **Confidencialidade**: garante que apenas pessoas autorizadas consigam ler os dados. Exemplo: quando você acessa seu banco pelo celular, a criptografia impede que alguém intercepte suas informações financeiras.
- **Integridade**: garante que os dados não foram alterados durante o trânsito. Se alguém modificar uma mensagem cifrada, o destinatário consegue detectar a adulteração.
- **Autenticação**: confirma a identidade de quem enviou os dados. Certificados digitais, por exemplo, usam criptografia para provar que um site é realmente quem diz ser.
- **Não-repúdio**: impede que o autor negue ter enviado uma mensagem. Assinaturas digitais fornecem prova matemática de autoria.

No dia a dia, a criptografia está presente em praticamente tudo:

- **HTTPS**: o cadeado no navegador indica que a comunicação com o site é cifrada.
- **Mensageiros**: aplicativos como WhatsApp e Signal usam criptografia ponta a ponta.
- **Internet banking**: todas as transações são protegidas por múltiplas camadas criptográficas.
- **Wi-Fi**: o protocolo WPA2/WPA3 cifra o tráfego da sua rede sem fio.

### 1.3 Conceitos Fundamentais

Antes de avançarmos, é importante entender alguns termos que serão usados ao longo deste documento:

- **Texto claro** (*plaintext*): a informação original, legível. Exemplo: a mensagem "Olá, mundo!".
- **Texto cifrado** (*ciphertext*): o resultado da criptografia — dados embaralhados e ilegíveis. Exemplo: `a7f3b2c9e1d8...`.
- **Chave** (*key*): um valor secreto usado para cifrar e/ou decifrar os dados. Quanto maior a chave, mais difícil é quebrar a criptografia.
- **Cifrar** (*encrypt*): o processo de transformar texto claro em texto cifrado usando um algoritmo e uma chave.
- **Decifrar** (*decrypt*): o processo reverso — transformar texto cifrado de volta em texto claro usando a chave correta.
- **Algoritmo**: o procedimento matemático que define como os dados são cifrados e decifrados. Exemplos: AES, RSA.

---

## 2. Criptografia Simétrica vs Assimétrica

Existem duas grandes categorias de criptografia. Entender a diferença entre elas é fundamental para saber quando e como usar cada uma.

### 2.1 Criptografia Simétrica

Na criptografia simétrica, **a mesma chave** é usada tanto para cifrar quanto para decifrar os dados.

Analogia: imagine uma porta com uma fechadura comum. A mesma chave que tranca também destranca. Se você quer que outra pessoa abra a porta, precisa entregar uma cópia da chave a ela.

**Vantagens:**

- Extremamente rápida — ideal para grandes volumes de dados.
- Algoritmos eficientes que podem ser acelerados por hardware.

**Desvantagem principal:**

- O **problema da distribuição de chaves**: como entregar a chave com segurança ao destinatário? Se alguém interceptar a chave durante a troca, toda a comunicação fica comprometida.

O algoritmo simétrico mais utilizado atualmente é o **AES** (detalhado na seção 4).

### 2.2 Criptografia Assimétrica

Na criptografia assimétrica, são usadas **duas chaves matematicamente relacionadas**: uma **chave pública** e uma **chave privada**.

- A **chave pública** pode ser compartilhada livremente com qualquer pessoa.
- A **chave privada** deve ser mantida em segredo absoluto.

O que uma chave cifra, somente a outra consegue decifrar.

Analogia: imagine uma caixa de correio pública. Qualquer pessoa pode depositar uma carta pela abertura (cifrar com a chave pública), mas somente o dono da caixa, que possui a chave da tranca, consegue abrir e ler as cartas (decifrar com a chave privada).

**Vantagens:**

- Resolve o problema da distribuição de chaves — a chave pública pode ser enviada abertamente.
- Permite assinaturas digitais e certificados.

**Desvantagens:**

- Significativamente mais lenta que a criptografia simétrica.
- O tamanho dos dados que podem ser cifrados é limitado pelo tamanho da chave.

O algoritmo assimétrico mais utilizado é o **RSA** (detalhado na seção 5).

### 2.3 Comparação Direta

| Característica | Simétrica | Assimétrica |
|---|---|---|
| Número de chaves | 1 (compartilhada) | 2 (pública + privada) |
| Velocidade | Rápida | Lenta |
| Tamanho dos dados | Ilimitado | Limitado pelo tamanho da chave |
| Distribuição de chave | Problemática (precisa de canal seguro) | Simplificada (chave pública é aberta) |
| Uso típico | Cifrar dados em massa | Troca de chaves, assinaturas digitais |
| Exemplo de algoritmo | AES | RSA |

### 2.4 Criptografia Híbrida

Na prática, os dois tipos são usados **juntos** em um modelo chamado **criptografia híbrida**. Esse é o modelo usado por praticamente todos os protocolos modernos de segurança (TLS/HTTPS, PGP, S/MIME).

O funcionamento é:

1. Uma **chave simétrica aleatória** (chamada de chave de sessão) é gerada.
2. Os **dados são cifrados** com essa chave simétrica (rápido, sem limite de tamanho).
3. A **chave simétrica é cifrada** com a chave pública RSA do destinatário (resolve a distribuição).
4. O destinatário usa sua **chave privada RSA** para decifrar a chave simétrica.
5. Com a chave simétrica recuperada, o destinatário **decifra os dados**.

Dessa forma, obtém-se o melhor dos dois mundos: a velocidade da criptografia simétrica e a segurança na troca de chaves da criptografia assimétrica.

---

## 3. Funções Hash

Funções hash são frequentemente usadas em conjunto com algoritmos de criptografia (por exemplo, no padding OAEP do RSA e na autenticação do GCM no AES). Por isso, é importante entendê-las antes de mergulhar nos detalhes do AES e RSA.

### 3.1 O que é uma Função Hash

Uma **função hash criptográfica** é uma função matemática que recebe uma entrada de qualquer tamanho e produz uma saída de tamanho fixo, chamada de **digest** ou **hash**. A operação é **unidirecional**: é computacionalmente inviável recuperar a entrada original a partir do hash.

Analogia: pense em uma impressão digital. Cada pessoa tem uma impressão digital única que a identifica, mas olhando para a impressão digital, você não consegue reconstruir a pessoa inteira. Da mesma forma, o hash é uma "impressão digital" dos dados.

### 3.2 Propriedades Essenciais

Uma boa função hash criptográfica deve possuir:

- **Determinismo**: a mesma entrada sempre produz o mesmo hash.
- **Efeito avalanche**: uma mudança mínima na entrada (até mesmo um único bit) gera um hash completamente diferente.
- **Resistência à pré-imagem**: dado um hash, é inviável encontrar uma entrada que produza esse hash.
- **Resistência à segunda pré-imagem**: dada uma entrada, é inviável encontrar outra entrada diferente que produza o mesmo hash.
- **Resistência a colisões**: é inviável encontrar duas entradas distintas que produzam o mesmo hash.

### 3.3 Algoritmos de Hash

#### SHA-1 (Secure Hash Algorithm 1)

| Propriedade | Valor |
|---|---|
| Tamanho da saída | 160 bits (20 bytes) |
| Tamanho do bloco interno | 512 bits |
| Status | **DESCONTINUADO** |

O SHA-1 foi amplamente usado por décadas, mas em 2017, pesquisadores do Google e do CWI Amsterdam demonstraram a primeira colisão prática (ataque SHAttered), provando que duas entradas diferentes podiam produzir o mesmo hash SHA-1. Desde então, o SHA-1 é considerado **inseguro** e não deve ser usado em novos sistemas. Ainda é encontrado em sistemas legados por questões de compatibilidade.

#### SHA-2 (Família)

A família SHA-2, padronizada pelo NIST no FIPS 180-4, é o padrão atual e amplamente utilizado:

| Variante | Tamanho da Saída | Tamanho do Bloco Interno | Uso Comum |
|---|---|---|---|
| SHA-224 | 224 bits (28 bytes) | 512 bits | Pouco usado, compatibilidade |
| SHA-256 | 256 bits (32 bytes) | 512 bits | **Padrão recomendado** para uso geral |
| SHA-384 | 384 bits (48 bytes) | 1024 bits | Alta segurança |
| SHA-512 | 512 bits (64 bytes) | 1024 bits | Alta segurança, eficiente em 64 bits |

O **SHA-256** é a escolha mais comum e recomendada para a maioria dos cenários, oferecendo um bom equilíbrio entre segurança e desempenho.

#### SHA-3 (Família)

O SHA-3 foi padronizado pelo NIST em 2015 (FIPS 202) e é baseado no algoritmo **Keccak**, que utiliza uma construção interna completamente diferente do SHA-2 (chamada *sponge construction*). Ele **não é um substituto** do SHA-2 (que continua seguro), mas sim uma **alternativa** com uma arquitetura distinta, oferecendo diversidade criptográfica.

| Variante | Tamanho da Saída | Tamanho do Bloco Interno (rate) |
|---|---|---|
| SHA3-256 | 256 bits (32 bytes) | 1088 bits |
| SHA3-512 | 512 bits (64 bytes) | 576 bits |

### 3.4 Aplicações de Funções Hash

- **Verificação de integridade**: verificar se um arquivo foi corrompido ou adulterado durante o download.
- **Armazenamento de senhas**: armazena-se o hash da senha, não a senha em si. (Na prática, usa-se funções especializadas como Argon2, bcrypt ou PBKDF2, que adicionam *salt* e são deliberadamente lentas.)
- **Assinaturas digitais**: o documento é primeiro "hashado" e depois o hash é assinado com a chave privada (*hash-then-sign*).
- **HMAC**: *Hash-based Message Authentication Code* — combina uma chave secreta com o hash para verificar autenticidade e integridade simultaneamente.
- **Padding OAEP**: o esquema de padding OAEP do RSA usa funções hash internamente (detalhado na seção 5.4).

---

## 4. AES (Advanced Encryption Standard)

O AES é o algoritmo de criptografia simétrica mais utilizado no mundo. Ele é um padrão do governo dos Estados Unidos e é adotado globalmente em praticamente todos os protocolos e sistemas de segurança modernos.

### 4.1 História

Na década de 1990, o **DES** (*Data Encryption Standard*), que havia sido o padrão desde 1977, estava claramente envelhecendo. Com uma chave de apenas 56 bits, ele já podia ser quebrado por força bruta — em 1999, uma máquina dedicada quebrou o DES em menos de 24 horas.

Em **janeiro de 1997**, o NIST (*National Institute of Standards and Technology*) lançou uma chamada pública internacional para propor um novo padrão de criptografia. O processo foi aberto e transparente:

- **15 algoritmos** foram submetidos por equipes de todo o mundo.
- **5 finalistas** foram selecionados: Rijndael, Serpent, Twofish, RC6 e MARS.
- Em **outubro de 2000**, o NIST anunciou o vencedor: **Rijndael**.

O Rijndael foi desenvolvido por dois criptógrafos belgas, **Joan Daemen** e **Vincent Rijmen**, do laboratório ESAT/COSIC da Universidade KU Leuven, na Bélgica. A escolha surpreendeu muitos observadores, que não esperavam que o governo americano adotasse um padrão criado por não-americanos — o que demonstrou a seriedade e imparcialidade do processo de seleção.

Em **26 de novembro de 2001**, o AES foi oficialmente publicado como **FIPS 197** pelo NIST.

### 4.2 Como Funciona

O AES é uma **cifra de bloco** (*block cipher*): ele opera sobre blocos de dados de tamanho fixo de **128 bits (16 bytes)**. Se os dados a serem cifrados forem maiores que 128 bits, é necessário um **modo de operação** (seção 4.4) para processar múltiplos blocos.

Internamente, o AES utiliza uma **rede de substituição-permutação** (*substitution-permutation network* — SPN). Os dados passam por múltiplas rodadas (*rounds*) de transformação, onde cada rodada aplica quatro operações:

1. **SubBytes** — Cada byte do bloco é substituído por outro usando uma tabela de substituição (S-box). Essa etapa introduz **não-linearidade**, essencial para a segurança.

2. **ShiftRows** — As linhas da matriz de estado (4×4 bytes) são deslocadas ciclicamente. A primeira linha não muda, a segunda é deslocada 1 posição, a terceira 2 posições e a quarta 3 posições. Isso garante **difusão** entre as colunas.

3. **MixColumns** — Cada coluna da matriz é transformada por uma multiplicação de matrizes no campo GF(2⁸). Isso proporciona **difusão** adicional, fazendo com que cada byte de saída dependa de todos os bytes da coluna de entrada. (Esta etapa é omitida na última rodada.)

4. **AddRoundKey** — O bloco é combinado (XOR) com uma subchave derivada da chave principal. Sem essa etapa, as operações anteriores seriam apenas uma substituição fixa que poderia ser pré-computada.

### 4.3 Tamanhos de Chave

O AES suporta três tamanhos de chave. A diferença principal é o número de rodadas de transformação:

| Tamanho da Chave | Número de Rounds | Nível de Segurança |
|---|---|---|
| 128 bits (16 bytes) | 10 | Seguro para uso geral |
| 192 bits (24 bytes) | 12 | Margem de segurança adicional |
| 256 bits (32 bytes) | 14 | Máximo — exigido para dados classificados pelo governo dos EUA |

Todos os três tamanhos são considerados seguros atualmente. O **AES-128** é suficiente para a grande maioria dos casos de uso. O **AES-256** é recomendado quando se deseja uma margem de segurança extra contra possíveis avanços futuros (incluindo computação quântica, onde o algoritmo de Grover reduziria efetivamente a segurança do AES-256 para ~128 bits simétricos).

### 4.4 Modos de Operação

Como o AES opera em blocos de 128 bits, é necessário um **modo de operação** para cifrar dados maiores que um único bloco. Cada modo define como os blocos são processados e encadeados, e cada um tem propriedades de segurança e desempenho distintas.

#### 4.4.1 ECB (Electronic Codebook)

**Referência**: NIST SP 800-38A

Cada bloco é cifrado **independentemente** com a mesma chave. Não utiliza IV (*Initialization Vector*).

```
Bloco 1 → AES(chave) → Bloco cifrado 1
Bloco 2 → AES(chave) → Bloco cifrado 2
Bloco 3 → AES(chave) → Bloco cifrado 3
```

**INSEGURO para a maioria dos usos.** O principal problema é que blocos de texto claro idênticos produzem blocos cifrados idênticos, o que vaza padrões dos dados originais. O exemplo clássico é o "pinguim ECB": ao cifrar uma imagem com ECB, a silhueta da imagem original permanece claramente visível no resultado cifrado.

O ECB só é aceitável em cenários muito específicos, como cifrar um único bloco de dados (por exemplo, uma única chave AES).

#### 4.4.2 CBC (Cipher Block Chaining)

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

#### 4.4.3 CTR (Counter)

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

#### 4.4.4 GCM (Galois/Counter Mode)

**Referência**: NIST SP 800-38D (2007)

O GCM combina o modo **CTR** (para confidencialidade) com a autenticação **GHASH** (baseada em multiplicação no campo de Galois). É um modo **AEAD** (*Authenticated Encryption with Associated Data*), o que significa que ele fornece **confidencialidade e autenticidade** simultaneamente.

**Características:**

- Produz uma **tag de autenticação** (tipicamente 128 bits) que permite verificar se os dados foram adulterados.
- Suporta **AAD** (*Additional Authenticated Data*): dados que são autenticados mas não cifrados (como cabeçalhos de protocolo).
- O nonce/IV recomendado é de **96 bits (12 bytes)** — comprimentos diferentes são suportados mas reduzem a segurança.
- Totalmente **paralelizável**.
- O **nonce nunca deve ser reutilizado** com a mesma chave. A reutilização no GCM é catastrófica: permite recuperar a chave de autenticação e forjar mensagens.

O GCM é o **modo recomendado para a maioria das aplicações** modernas. Ele é usado no TLS 1.3, SSH, IPsec e muitos outros protocolos.

#### 4.4.5 CFB (Cipher Feedback)

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

#### 4.4.6 OFB (Output Feedback)

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

#### 4.4.7 CCM (Counter with CBC-MAC)

**Referência**: NIST SP 800-38C, RFC 3610

O CCM combina o modo **CTR** (para confidencialidade) com **CBC-MAC** (para autenticação). Assim como o GCM, é um modo **AEAD**.

**Características:**

- Requer **dois passes** sobre os dados (um para o MAC, outro para a cifragem), ao contrário do GCM que faz em um único passe.
- O nonce tem tamanho entre **7 e 13 bytes** (padrão: 11 bytes). Existe uma relação inversa: L + N = 15, onde L é o campo que define o tamanho máximo da mensagem e N é o tamanho do nonce.
- Suporta AAD.
- Amplamente usado em **IEEE 802.11i (Wi-Fi WPA2)** e **Bluetooth**.
- Menos eficiente que o GCM, mas pode ser preferido em ambientes com restrições de hardware.

### 4.5 Comparação dos Modos de Operação

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

### 4.6 Padding (Preenchimento)

O padding é necessário apenas para **modos de bloco** (ECB e CBC), onde o texto claro precisa ser um múltiplo exato de 16 bytes (128 bits). Modos de fluxo (CTR, CFB, OFB) e modos autenticados (GCM, CCM) não precisam de padding.

#### 4.6.1 PKCS#7

**Referência**: RFC 5652

O esquema de padding mais utilizado e recomendado. Preenche com N bytes, cada um com o valor N (onde N é a quantidade de bytes necessários para completar o bloco).

```
Dados:    [0x48 0x65 0x6C 0x6C 0x6F]              (5 bytes — "Hello")
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B]
                                                    (11 bytes de padding, cada um = 0x0B)
```

Se os dados já forem múltiplo de 16, um **bloco inteiro de padding é adicionado** (16 bytes de valor 0x10). Isso garante que o padding é sempre **inequivocamente reversível**.

#### 4.6.2 ISO 7816-4

**Referência**: ISO/IEC 7816-4

Também chamado de *bit padding*. Preenche com o byte `0x80` seguido de bytes `0x00` até completar o bloco.

```
Dados:    [0x48 0x65 0x6C 0x6C 0x6F]
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x80 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
```

Originalmente usado em aplicações de **smart cards**. Também é inequivocamente reversível, já que o marcador `0x80` indica onde o padding começa.

#### 4.6.3 Zero Padding

Preenche com bytes `0x00` até completar o bloco.

```
Dados:    [0x48 0x65 0x6C 0x6C 0x6F]
Padding:  [0x48 0x65 0x6C 0x6C 0x6F 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
```

**Problema**: se o texto claro terminar com bytes `0x00`, é impossível distinguir os bytes reais dos bytes de padding. Isso torna o zero padding **ambíguo para dados binários** e não recomendado para uso geral. Pode ser aceitável quando se sabe que os dados são exclusivamente texto.

#### 4.6.4 Sem Padding (No Padding)

Nenhum preenchimento é adicionado. O texto claro **deve** ter tamanho exato múltiplo de 16 bytes. Caso contrário, a operação falhará.

Usado com modos de fluxo (CTR, CFB, OFB) e modos autenticados (GCM, CCM), que operam em nível de byte e não exigem alinhamento de bloco.

#### Comparação dos Esquemas de Padding

| Esquema | Reversível sem Ambiguidade | Quando Usar |
|---|---|---|
| PKCS#7 | Sim | **Recomendado** para ECB e CBC |
| ISO 7816-4 | Sim | Smart cards ou quando exigido por padrão |
| Zero Padding | Não (dados binários) | Apenas texto — uso legado |
| Sem Padding | N/A | CTR, GCM, CFB, OFB, CCM |

### 4.7 Considerações de Segurança

- **Nunca reutilize nonce/IV com a mesma chave.** No CTR e GCM, a reutilização é catastrófica. No CBC, compromete a confidencialidade dos blocos iniciais.
- **Sempre prefira modos autenticados** (GCM ou CCM). Sem autenticação, um atacante pode alterar o texto cifrado de formas que produzem alterações previsíveis no texto claro.
- **Nunca use ECB** para dados maiores que um bloco, pois ele vaza padrões.
- **Derivação de chaves**: nunca use uma senha diretamente como chave AES. Use funções de derivação de chaves como PBKDF2, HKDF ou Argon2 para transformar uma senha em uma chave criptográfica adequada.
- **Geração de IV/nonce**: use sempre um gerador de números aleatórios criptograficamente seguro (CSPRNG).

---

## 5. RSA (Rivest-Shamir-Adleman)

O RSA é o algoritmo de criptografia assimétrica mais conhecido e utilizado. Ele pode ser usado tanto para **cifragem** quanto para **assinaturas digitais**.

### 5.1 História

Em **1977**, três pesquisadores do MIT — **Ron Rivest**, **Adi Shamir** e **Leonard Adleman** — publicaram o primeiro criptossistema de chave pública prático. Rivest e Shamir, ambos cientistas da computação, propunham funções candidatas, enquanto Adleman, matemático, tentava quebrá-las. Após 42 tentativas fracassadas, em abril de 1977, Rivest formalizou a ideia que se tornaria o RSA.

O algoritmo foi publicado na revista **Scientific American** em 1977 e rapidamente se tornou o padrão para criptografia de chave pública. A patente americana do RSA expirou em **setembro de 2000**, tornando-o livre para uso em todo o mundo.

O nome "RSA" vem das iniciais dos sobrenomes dos três criadores: **R**ivest, **S**hamir e **A**dleman.

### 5.2 Como Funciona

A segurança do RSA é baseada em um problema matemático: a **dificuldade de fatorar o produto de dois números primos muito grandes**. Multiplicar dois primos é rápido, mas dado apenas o resultado, encontrar os fatores originais é computacionalmente inviável para números suficientemente grandes.

#### Geração de Chaves

1. Escolhem-se dois números primos grandes **p** e **q** (cada um com centenas de dígitos).
2. Calcula-se **n = p × q** (o módulo). Este valor é público.
3. Calcula-se **φ(n) = (p − 1) × (q − 1)** (a função totiente de Euler).
4. Escolhe-se um expoente público **e**, coprimo a φ(n). O valor mais utilizado é **e = 65537** (0x10001), escolhido por ser primo e ter poucos bits ativos (eficiente para exponenciação).
5. Calcula-se o expoente privado **d = e⁻¹ mod φ(n)** (o inverso modular de e).

- **Chave pública**: (n, e)
- **Chave privada**: (n, d)

#### Cifragem e Decifragem

- **Cifrar**: c = m^e mod n (onde m é a mensagem numérica e c é o texto cifrado)
- **Decifrar**: m = c^d mod n

A segurança depende do fato de que, sem conhecer p e q (que compõem d), é computacionalmente inviável calcular d a partir de apenas (n, e).

### 5.3 Tamanhos de Chave

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

O tamanho da chave também limita o **tamanho máximo dos dados** que podem ser cifrados diretamente (detalhado na seção 5.4).

### 5.4 Esquemas de Padding

No RSA, a mensagem em texto claro precisa ser transformada em um número entre 0 e n−1 antes da cifragem. O **padding** (ou esquema de codificação) é o processo que faz essa transformação de forma segura. Cifrar sem padding (chamado "textbook RSA") é extremamente inseguro.

#### 5.4.1 PKCS#1 v1.5

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

#### 5.4.2 OAEP (Optimal Asymmetric Encryption Padding)

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

#### Versões do OAEP

| Versão | Referência | Detalhes |
|---|---|---|
| OAEP v1 | Bellare-Rogaway (1994) | Proposta original com SHA-1 |
| OAEP v2.0 | PKCS#1 v2.0 (RFC 2437) | Incorporação ao padrão PKCS#1 com MGF1 |
| OAEP v2.1 | PKCS#1 v2.1 (RFC 3447) / v2.2 (RFC 8017) | **Recomendado** — hash configurável, MGF1, suporte a label |

> **Recomendação**: use sempre **OAEP v2.1** (ou posterior) com **SHA-256** ou superior. Conforme a RFC 8017: *"RSAES-OAEP is required to be supported for new applications"*.

### 5.5 Algoritmos de Hash Usados com RSA

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

### 5.6 Formatos de Chave

Chaves RSA podem ser armazenadas e transmitidas em diferentes formatos padronizados. Cada formato tem um propósito específico.

#### 5.6.1 PKCS#1

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

#### 5.6.2 PKCS#8 (PrivateKeyInfo)

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

#### 5.6.3 X.509 (SubjectPublicKeyInfo)

**Referência**: RFC 5280

Formato **genérico** para chaves públicas, amplamente usado em certificados digitais. Encapsula a chave pública com um identificador de algoritmo.

```
-----BEGIN PUBLIC KEY-----
(dados codificados em Base64)
-----END PUBLIC KEY-----
```

#### Comparação dos Formatos

| Formato | Tipo de Chave | Específico para RSA? | PEM Header |
|---|---|---|---|
| PKCS#1 | Pública e Privada | Sim | `BEGIN RSA PUBLIC KEY` / `BEGIN RSA PRIVATE KEY` |
| PKCS#8 | Apenas Privada | Não (genérico) | `BEGIN PRIVATE KEY` |
| X.509 | Apenas Pública | Não (genérico) | `BEGIN PUBLIC KEY` |

### 5.7 Considerações de Segurança

- **Tamanho mínimo de chave**: use no mínimo **2048 bits**. Chaves de 1024 bits são consideradas obsoletas.
- **Sempre use OAEP**: evite PKCS#1 v1.5 para cifragem em novos projetos devido à vulnerabilidade Bleichenbacher.
- **Não cifre dados grandes diretamente**: o RSA é limitado pelo tamanho da chave. Para dados maiores, use criptografia híbrida (seção 2.4).
- **Geração de primos**: a qualidade do gerador de números aleatórios é crítica. Primos previsíveis comprometem completamente a segurança.
- **Ameaça quântica**: o **algoritmo de Shor** permite que um computador quântico suficientemente grande fatore números inteiros em tempo polinomial, o que quebraria o RSA. Embora computadores quânticos dessa capacidade ainda não existam, organizações sensíveis já estão planejando a migração para algoritmos pós-quânticos (como os selecionados pelo NIST: CRYSTALS-Kyber para cifragem e CRYSTALS-Dilithium para assinaturas).

---

## 6. Quando Usar AES vs RSA

### 6.1 Cenários para AES

- **Cifragem de arquivos e bancos de dados**: volumes grandes de dados onde a velocidade é essencial.
- **Tráfego de rede**: após a negociação de chaves (TLS), todo o tráfego é cifrado com AES.
- **Criptografia de disco**: soluções como BitLocker, FileVault e LUKS usam AES.
- **Quando ambas as partes já compartilham uma chave**: não há necessidade de troca de chaves.

### 6.2 Cenários para RSA

- **Troca de chaves**: enviar uma chave AES de forma segura para outra parte.
- **Assinaturas digitais**: assinar documentos, código ou certificados.
- **Autenticação baseada em certificados**: TLS, SSH, certificados X.509.
- **Quando as partes não possuem segredo compartilhado**: a chave pública pode ser distribuída abertamente.

### 6.3 Tabela de Decisão

| Necessidade | Algoritmo Recomendado |
|---|---|
| Cifrar grandes volumes de dados | AES (preferencialmente GCM) |
| Trocar chaves com segurança | RSA-OAEP |
| Assinar dados digitalmente | RSA + SHA-256 (ou superior) |
| Cifrar e autenticar simultaneamente | AES-GCM ou AES-CCM |
| Cifrar dados e enviar a desconhecidos | Criptografia híbrida (RSA + AES) |
| Armazenar senhas | Não use AES nem RSA — use Argon2, bcrypt ou PBKDF2 |

---

## 7. Referências

### Padrões NIST (FIPS)

- [**FIPS 197**](https://csrc.nist.gov/pubs/fips/197/final) — Advanced Encryption Standard (AES). NIST, 2001 (atualizado 2023).
- [**FIPS 180-4**](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) — Secure Hash Standard (SHS): SHA-1, SHA-224, SHA-256, SHA-384, SHA-512. NIST, 2015.
- [**FIPS 202**](https://csrc.nist.gov/pubs/fips/202/final) — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions. NIST, 2015.

### Publicações Especiais NIST (SP)

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
