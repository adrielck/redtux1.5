# RedTux 1.5 — Interactive Recon & Exploitation Toolkit

## Visão Geral
RedTux 1.5 evolui o clássico RedTux 1.2 transformando‑o em uma **ferramenta interativa** via terminal, com menu guiado, validação automática de dependências e novas funções de coleta de informações e pós-exploração.

### Principais Melhorias
- **Menu interativo** com seleção por número, ajuda em tela e pausa após cada ação.
- **Validação de dependências**: detecta ausência de `sublist3r`, `msfconsole`, `paramiko`, `impacket`, `curl`, `whois`/`tracert` e emite alertas claros.
- **Fallback de cores**: se `colorama` não estiver instalado, o script continua sem quebrar.
- **Thread pool configurável** para port scanning, agora com até 50 threads por padrão.
- **Prompt dinâmico**: solicita inputs passo‑a‑passo para cada função, sem necessidade de reexecutar o script com argumentos CLI.

### Novas Funcionalidades
| Opção no Menu | Função                              | Descrição                                                                                   |
|---------------|-------------------------------------|---------------------------------------------------------------------------------------------|
| 1             | Port scan                           | Escaneamento multithreaded (TCP connect) com saída opcional em JSON.                        |
| 2             | DNS lookup                          | Resolve `A` records via socket nativo.                                                     |
| 3             | Subdomain recon (Sublist3r)         | Executa `sublist3r -d DOMAIN [-o OUTPUT]`.                                                 |
| 4             | HTTP banner grab                    | Coleta banner HTTP enviando requisição `HEAD`.                                             |
| 5             | Whois lookup                        | Chama utilitário `whois` (ou módulo Python).                                               |
| 6             | Traceroute                          | Usa `tracert` (Windows) ou `traceroute` (Linux/macOS).                                      |
| 7             | Metasploit exploit                  | Invoca `msfconsole -q -x "...; exploit; exit"`.                                            |
| 8             | SSH exec (Paramiko)                 | Conecta via SSH, executa comando e exibe saída.                                            |
| 9             | SMB enum (Impacket)                 | Lista shares SMB usando Impacket.                                                           |
| 10            | Obfuscate/Deobfuscate (Base64)      | Codifica ou decodifica texto via Base64.                                                   |
| 11            | Exfiltrate file (curl)              | Envia arquivo para URL via `curl -F file=@path`.                                           |
| 12            | Clear logs                          | Apaga todos os `*.log` em diretório especificado.                                          |
| 0             | Exit                                | Encerra o menu.                                                                             |

### Features Removidas
- Execução via argumentos diretos CLI — agora toda a interação é via menu.
- Parser `argparse` foi retirado em favor de prompts interativos.
- Scripts de configuração de aliases/bat foram consolidados no README.

## Requisitos & Instalação

### Python & Pip
```bash
# Certifique‑se de ter Python 3.6+ e pip
pip install colorama paramiko impacket sublist3r python-whois
```

### Ferramentas de Sistema

| Ferramenta | Windows                                  | Linux/macOS                       |
|------------|------------------------------------------|-----------------------------------|
| traceroute | já incluso (`tracert`)                   | `sudo apt install traceroute`     |
| whois      | opcional via Chocolatey: `choco install whois` | `sudo apt install whois`          |
| curl       | [instalado por default no WSL ou via Git for Windows] | `sudo apt install curl`           |
| sublist3r  | pip (já acima)                           | pip (já acima)                    |
| msfconsole | Instalar Metasploit Framework            | Instalar Metasploit Framework     |

> **Nota:** em Windows, `tracert` substitui `traceroute` e não há `sudo` — rode o PowerShell/Python normalmente.

## Execução
1. Clone ou copie o script:
   ```bash
   git clone [[https://…/redtux.git]
   cd redtux
   ```
2. Torne o script executável (Linux/macOS):
   ```bash
   chmod +x redtux 1.5 .py
   ```
3. Execute:
   ```bash
   python redtux 1.5 .py
   ```
4. Navegue pelo **menu numérico**, digite o número da função, insira os parâmetros quando solicitado e pressione **Enter** para voltar ao menu principal.

---

### Estrutura de Código
- **`RedTux`**: classe central, mantém contadores, lista de ações e validações.
- **`menu_actions`**: dicionário que mapeia opções para métodos e descrições.
- Cada método:
  1. Verifica dependência (se aplicável).
  2. Solicita parâmetros via `input()`.
  3. Executa ação (biblioteca interna ou subprocess).
  4. Exibe resultado e pausa para o usuário.
- **Saída colorida** via `colorama`, com fallback silencioso.

---   
