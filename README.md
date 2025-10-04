# Script de Atualização de Firmware de OLTs Datacom

[](https://golang.org/)

Um script eficiente em Go para automatizar a atualização de firmware em OLTs Datacom, com busca de alvos via API Zabbix e um fluxo de remediação interativo e concorrente para tratar falhas de download.

## Como Usar

Este script foi projetado para ser robusto e interativo. Para executá-lo, siga os passos básicos:

1.  **Configure as constantes** no topo do arquivo `main.go`. É crucial definir corretamente as credenciais da API Zabbix (`ZABBIX_API_URL`, `ZABBIX_USER`, `ZABBIX_PASS`) e, principalmente, o comando de download do firmware desejado na constante `DOWNLOAD_COMMAND`.
2.  **Execute o script** no seu terminal com o Go instalado:
    ```bash
    go run main.go
    ```
3.  **Siga as instruções interativas** para fornecer as credenciais SSH e, se necessário, para escolher os firmwares a serem removidos durante a fase de remediação.

> **Guia Completo:** Para um guia detalhado sobre os pré-requisitos, o passo a passo de uso e uma explicação aprofundada sobre o funcionamento interno do script, **abra o arquivo `Documentacao.html` em seu navegador.**

-----

## Estrutura do Repositório

Aqui está uma explicação sobre cada arquivo e diretório presente neste repositório, para que você entenda o papel de cada um.

  * ### `main.go`

    **O coração do projeto.** Este é o arquivo principal que contém todo o código-fonte da aplicação em Go. É aqui que a mágica acontece: a conexão com a API do Zabbix, a execução paralela de comandos SSH e o fluxo interativo de remediação de falhas.

  * ### `Documentacao.html`

    **O manual do usuário completo.** Esta é uma página web autocontida que serve como a documentação oficial do script. Ela explica em detalhes os pré-requisitos, como configurar e usar a ferramenta, e também detalha o funcionamento técnico, incluindo a aplicação de paralelismo para otimizar a performance.

  * ### `go.mod`

    **O manifesto do projeto.** Este arquivo é o núcleo do sistema de módulos do Go. Ele é análogo a um `pom.xml` em um projeto Java ou um `package.json` em Node.js. Suas funções principais são:

    1.  Definir o nome do módulo (o caminho do nosso projeto).
    2.  Listar as dependências diretas que o nosso `main.go` utiliza (como o pacote `golang.org/x/crypto/ssh`).

  * ### `go.sum`

    **O arquivo de "lock" das dependências.** Enquanto o `go.mod` lista as dependências que *queremos*, o `go.sum` garante que sempre usaremos as *mesmas versões exatas* dessas dependências (e das dependências delas). Ele contém as hashes criptográficas de cada versão de cada pacote, garantindo que as compilações (builds) sejam 100% reprodutíveis e seguras, evitando que uma atualização inesperada de um pacote quebre o nosso script.

  * ### `VersaoAntigaEmPython/`

    **O arquivo histórico.** Este diretório contém o script original em Python que serviu como base para este projeto. Ele foi mantido no repositório por dois motivos:

    1.  **Contexto Histórico:** Para que seja possível consultar como a automação era feita anteriormente.
    2.  **Comparativo de Performance:** Permite que usuários curiosos executem ambas as versões e comparem diretamente a diferença de velocidade e abordagem entre a execução sequencial do Python e a execução concorrente do Go.
