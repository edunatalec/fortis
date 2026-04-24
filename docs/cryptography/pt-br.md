# Criptografia

Um guia completo sobre criptografia, abordando desde conceitos fundamentais até os princípios por trás das principais técnicas criptográficas.

## Sumário

- [1. O que é Criptografia?](#1-o-que-é-criptografia)
- [2. Criptografia Simétrica vs Assimétrica](#2-criptografia-simétrica-vs-assimétrica)
- [3. Funções Hash](#3-funções-hash)
- [4. Casos de Uso da Criptografia](#4-casos-de-uso-da-criptografia)
- [5. Quando Usar Cada Tipo](#5-quando-usar-cada-tipo)
- [6. Referências](#6-referências)

---

## 1. O que é Criptografia?

### 1.1 Definição

A palavra **criptografia** vem do grego: *kryptós* (escondido, secreto) e *gráphein* (escrita). Em termos simples, criptografia é a ciência de transformar informações legíveis em algo incompreensível, de modo que apenas quem possui a "chave" correta consiga reverter o processo e ler a informação original.

Pense em um cofre: qualquer pessoa pode ver o cofre, mas somente quem tem a chave (ou a combinação) consegue abrir e acessar o que está dentro. A criptografia funciona da mesma forma — ela "tranca" seus dados para que apenas destinatários autorizados possam "destrancar" e lê-los.

### 1.2 Por que a Criptografia é Importante?

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

O algoritmo simétrico mais utilizado atualmente é o **AES**.

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

O algoritmo assimétrico mais utilizado é o **RSA**.

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
3. A **chave simétrica é cifrada** com a chave pública do destinatário (resolve a distribuição).
4. O destinatário usa sua **chave privada** para decifrar a chave simétrica.
5. Com a chave simétrica recuperada, o destinatário **decifra os dados**.

Dessa forma, obtém-se o melhor dos dois mundos: a velocidade da criptografia simétrica e a segurança na troca de chaves da criptografia assimétrica.

---

## 3. Funções Hash

Funções hash são frequentemente usadas em conjunto com algoritmos de criptografia e desempenham um papel fundamental em muitos protocolos criptográficos. Por isso, é importante entendê-las como parte de qualquer base em criptografia.

### 3.1 O que é uma Função Hash?

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

---

## 4. Casos de Uso da Criptografia

A criptografia é a espinha dorsal da segurança digital moderna. Abaixo estão os cenários mais comuns do mundo real onde técnicas criptográficas são aplicadas.

### 4.1 HTTPS/TLS (Proteção do Tráfego Web)

Toda vez que você vê o ícone do cadeado no seu navegador, o TLS (Transport Layer Security) está em ação. Ele usa uma combinação de criptografia assimétrica (para o handshake inicial e a troca de chaves) e criptografia simétrica (para cifrar o fluxo real de dados). Isso protege tudo, desde credenciais de login até compras online, contra interceptação e adulteração.

### 4.2 Criptografia Ponta a Ponta (WhatsApp, Signal)

Aplicativos de mensagens como WhatsApp e Signal implementam criptografia ponta a ponta, o que significa que apenas o remetente e o destinatário podem ler as mensagens. Nem mesmo o provedor do serviço tem acesso ao conteúdo. Isso é alcançado por meio de uma combinação de protocolos de acordo de chaves e criptografia simétrica, garantindo que as mensagens permaneçam privadas durante todo o seu percurso.

### 4.3 Cofres de Senhas

Gerenciadores de senhas como 1Password, Bitwarden e KeePass usam criptografia simétrica forte para proteger suas credenciais armazenadas. Uma única senha mestra deriva uma chave de criptografia (normalmente via PBKDF2 ou Argon2), que então cifra todo o cofre. Sem a senha mestra, os dados armazenados são computacionalmente inacessíveis.

### 4.4 Assinaturas Digitais

Assinaturas digitais usam criptografia assimétrica para garantir a autoria e a integridade de documentos, software e certificados. O signatário usa sua chave privada para assinar um hash dos dados, e qualquer pessoa com a chave pública correspondente pode verificar a assinatura. Essa é a base da assinatura de código, das assinaturas de documentos PDF e da infraestrutura de certificados X.509 que sustenta a internet.

### 4.5 Criptografia de Disco/Armazenamento

Soluções de criptografia de disco completo como BitLocker (Windows), FileVault (macOS) e LUKS (Linux) usam criptografia simétrica para proteger todos os dados em um dispositivo de armazenamento. Se o dispositivo for perdido ou roubado, os dados permanecem ilegíveis sem as credenciais corretas. Isso é crítico para laptops, unidades externas e qualquer dispositivo que possa sair de um ambiente seguro.

### 4.6 VPN (WireGuard, IPsec)

Redes Privadas Virtuais criam um túnel cifrado entre seu dispositivo e um servidor remoto, protegendo todo o tráfego de rede contra interceptação. Protocolos VPN modernos como o WireGuard usam acordo de chaves e criptografia simétrica de última geração para garantir tanto desempenho quanto segurança. O IPsec, outro protocolo amplamente implantado, usa uma combinação de troca de chaves e algoritmos simétricos para proteger as comunicações de rede na camada IP.

---

## 5. Quando Usar Cada Tipo

Escolher a abordagem criptográfica correta depende do seu cenário específico. Aqui está um guia prático para decidir entre abordagens simétricas, assimétricas, híbridas e de acordo de chaves.

### 5.1 Criptografia Simétrica

Use algoritmos simétricos (como AES ou ChaCha20) quando:

- **Cifrar grandes volumes de dados**: arquivos, bancos de dados, criptografia de disco ou fluxos de rede.
- **Ambas as partes já compartilham uma chave secreta**: não é necessária troca de chaves.
- **O desempenho é crítico**: a criptografia simétrica é ordens de grandeza mais rápida que a criptografia assimétrica.

### 5.2 Criptografia Assimétrica

Use algoritmos assimétricos (como RSA ou ECDSA) quando:

- **Assinar dados digitalmente**: documentos, código, certificados — provando autoria e integridade.
- **Autenticação baseada em certificados**: TLS, SSH, validação de certificados X.509.
- **As partes não possuem segredo pré-compartilhado**: a chave pública pode ser distribuída abertamente.

### 5.3 Criptografia Híbrida

Use abordagens híbridas quando:

- **Enviar dados cifrados para outra parte sem um segredo compartilhado**: gere uma chave simétrica aleatória, cifre os dados com ela e cifre a chave simétrica com a chave pública do destinatário.
- **Implementar protocolos de comunicação seguros**: TLS, PGP e S/MIME seguem esse modelo.

### 5.4 Acordo de Chaves

Use protocolos de acordo de chaves (como ECDH ou X25519) quando:

- **Estabelecer um segredo compartilhado sobre um canal inseguro**: ambas as partes contribuem para a criação de uma chave compartilhada sem que ela seja transmitida.
- **Sigilo futuro é necessário** (*forward secrecy*): o acordo de chaves efêmero garante que comprometer uma chave de longo prazo não comprometa sessões passadas.
- **Design de protocolos modernos**: WireGuard e TLS 1.3, por exemplo, preferem a troca de chaves baseada em ECDH ao transporte de chaves RSA.

### 5.5 Tabela de Decisão

| Necessidade | Abordagem Recomendada |
|---|---|
| Cifrar grandes volumes de dados | Criptografia simétrica (ex., AES-GCM, ChaCha20-Poly1305) |
| Trocar chaves com segurança | Acordo de chaves (ex., ECDH, X25519) ou criptografia assimétrica (ex., RSA-OAEP) |
| Assinar dados digitalmente | Assinaturas assimétricas (ex., RSA + SHA-256, ECDSA, Ed25519) |
| Cifrar e autenticar simultaneamente | Criptografia simétrica autenticada (ex., AES-GCM, ChaCha20-Poly1305) |
| Cifrar dados e enviar a desconhecidos | Criptografia híbrida (acordo de chaves ou assimétrico + simétrico) |
| Obter sigilo futuro | Acordo de chaves efêmero (ex., ECDHE) |
| Armazenar senhas | Não use criptografia — use Argon2, bcrypt ou PBKDF2 |

---

## 6. Referências

### Padrões NIST (FIPS)

- [**FIPS 180-4**](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) — Secure Hash Standard (SHS): SHA-1, SHA-224, SHA-256, SHA-384, SHA-512. NIST, 2015.
- [**FIPS 202**](https://csrc.nist.gov/pubs/fips/202/final) — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions. NIST, 2015.

### Publicações Especiais NIST (SP)

- [**NIST SP 800-57 Part 1 Rev. 5**](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) — Recommendation for Key Management: Part 1 – General. NIST, 2020.
