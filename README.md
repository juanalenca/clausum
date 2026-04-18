# Clausum - O Seu Cofre Digital 🔒

O **Clausum** é um gerenciador de backups e criptografia focado na privacidade agressiva de arquivos locais. Usando mecanismos encriptação `AES` simétrica (sob o módulo `Fernet`), ele empacota, comprime e tranca diretórios e arquivos vitais com senhas protegidas contra ataques de força-bruta através de derivação recursiva de chave. 

Idealizado como um "cofre de bolso" executável para computadores pessoais.

## Funcionalidades e Características 

- **🔒 Criptografia Avançada:** Usa `PBKDF2_HMAC` com SHA-256 (600.000 iterações) e *salt* randômico de 16-bytes acoplados à criptografia Fernet, abstraindo e fortalecendo a quebra do hash numérico.
- **📦 Buffer em Memória (I/O Streams):** A operação de zip e unzip das pastas inteiras acontece sob `io.BytesIO`. Isso previne a escrita de arquivos em disco temporários antes da criptografia, impossibilitando rastreio por ferramentas de varredura forenses de setor enquanto processa.
- **🛡️ Validador de Integridade Passiva:** O módulo de "Verificar Backup" consegue cruzar a assinatura de hash contra arquivos adulterados sem extrair o conteúdo real corrompido, poupando falhas e brechas de vírus em arquivos `zip` ocultos.
- **🚥 Validador Forte Interno:** Input protegido pela biblioteca `zxcvbn`, um estimador analítico rigoroso de quebra de entropia para coíbir senhas fracas.
- **🖥️ Interface Gráfica Responsiva:** Construída integralmente com a tecnologia _Modern GUI_ do `customtkinter`, proporcionando modo Dark robusto.

---

## Estrutura do Projeto

O repositório é configurado sob um padrão modular isolando `Views` das lógicas de segurança (Separation of Concerns).

```bash
/
├── archive/
│   ├── clausum-v1.py       # Versão retroativa sem verificação de integridade e UI antiga.
│   └── clausum-v2.py       # Versão retroativa V2.
├── src/
│   ├── main.py             # Instancia a engine do CustomTkinter, controler as views, tooltips e progresso.
│   └── crypto_utils.py     # Backend de criptografia: gerência a derivação de chave de sessão e o zip na memória.
└── README.md
```

---

## Como Utilizar 🛠️

Para rodar localmente a aplicação e começar a guardar seus dados:

1. Clone o repositório em sua máquina.
   ```bash
   git clone https://github.com/juanalenca/clausum.git
   ```

2. Certifique-se de que os pacotes essenciais do Python 3 estejam instalados. Crie e ative um ambiente visual para mantê-lo limpo e rode as dependências:
   ```bash
   pip install customtkinter cryptography zxcvbn
   ```

3. Execute o módulo principal a partir da raiz do repositório:
   ```bash
   cd clausum
   python src/main.py
   ```

4. Uma linda interface *Dark Mode* aparecerá na sua tela. Use a primeira etapa para selecionar os arquivos críticos, inserir a senha mestre (não a perca, os dados são inacessíveis de forma irreversível caso sejam esquecidots) e compactá-los no formato `.enc` (Encode Secure File). 

Recomenda-se realizar o backup dos dados importantes gerados pelo *Clausum* em um pendrive off-line.

---
_Aviso de Responsabilidade:_ Arquivos criptografados por este sistema em caso de extravio da chave, ou uso equivocado, não poderão ser recuperados por ferramentas de administração de partições tradicionais. Faça um bom gerenciamento de senhas.
