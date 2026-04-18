import os         # Para interagir com o sistema operacional (caminhos, pastas)
import zipfile    # Para compactar e descompactar arquivos .zip
import sys        # Para interagir com o sistema (saída de erros padrão)
import io         # Para trabalhar com fluxos de dados em memória (BytesIO)
import getpass    # Para solicitar senhas de forma segura (sem exibir na tela)
import base64     # Para codificar a chave derivada no formato esperado pelo Fernet
import hashlib    # Para usar a função de derivação de chave PBKDF2
from cryptography.fernet import Fernet, InvalidToken # A biblioteca principal para criptografia AES + HMAC


# DEFINIÇÃO DAS CONSTANTES DE SEGURANÇA

# Tamanho do "Sal" em bytes. 16 bytes (128 bits) é o padrão atual recomendado
SALT_SIZE = 16

# Número de iterações para a KDF (PBKDF2). Este é o "fator de trabalho".
# 600.000 é um valor moderno e seguro (recomendação OWASP para 2023+)
PBKDF2_ITERATIONS = 600_000


# FUNÇÕES CRIPTOGRÁFICAS E NÚCLEO

"""
Função que deriva uma chave de criptografia segura a partir da 
senha + "sal" aleatório + algoritmo PBKDF2 com HMAC-SHA256
"""
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = hashlib.pbkdf2_hmac( # implementação padrão e segura do PBKDF2 no Python
        'sha256', # algoritmo de hash interno usado pelo PBKDF2
        password.encode('utf-8'), # a senha do usuário (string) convertida para bytes
        salt, # valor aleatório único
        PBKDF2_ITERATIONS #n° de interações
    )
    # O resultado bruto do PBKDF2 (kdf) são bytes. A biblioteca Fernet espera a chave
    # no formato Base64 URL-Safe. Esta linha faz a conversão necessária.
    return base64.urlsafe_b64encode(kdf)


"""
    Compacta um arquivo ou diretório (recursivamente) em um objeto ZIP na memória.
    Retorna os bytes do arquivo ZIP resultante ou None se ocorrer um erro.
    Operar em memória evita salvar um arquivo .zip desprotegido no disco.
"""
def zip_source(source_path):
    # io.BytesIO cria um "arquivo" binário virtual na memória RAM.
    in_memory_zip = io.BytesIO()
    try:
        # Abre o "arquivo" em memória para escrita de ZIP, usando compressão DEFLATE.
        with zipfile.ZipFile(in_memory_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if os.path.isdir(source_path):
                # os.walk() é ideal para percorrer todos os subdiretórios e arquivos.
                for root, _, files in os.walk(source_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        # os.path.relpath calcula o caminho relativo do arquivo dentro da pasta original.
                        # Isso preserva a estrutura de diretórios dentro do ZIP sem incluir
                        # o caminho completo do sistema (ex: C:\Users\...).
                        archive_name = os.path.relpath(file_path, os.path.dirname(source_path))
                        # Adiciona o arquivo ao ZIP com seu caminho relativo.
                        zipf.write(file_path, arcname=archive_name)
            elif os.path.isfile(source_path):
                # Se a origem for um único arquivo, adiciona apenas ele.
                archive_name = os.path.basename(source_path)
                zipf.write(source_path, arcname=archive_name)
            else:
                # Se o caminho não for nem arquivo nem diretório válido.
                print(f"Erro: O caminho '{source_path}' não é um arquivo ou pasta válida.", file=sys.stderr)
                return None
    except Exception as e:
        print(f"Ocorreu um erro inesperado durante a compactação: {e}", file=sys.stderr)
        return None
    # Antes de retornar os bytes, move o "cursor" do arquivo em memória para o início.
    in_memory_zip.seek(0)
    # Retorna todo o conteúdo binário do ZIP que foi escrito na memória.
    return in_memory_zip.read()


# Extrai o conteúdo de dados ZIP (representados como bytes) para uma pasta de destino no disco.
def unzip_data(zip_data, destination_folder):
    try:
        # Garante que a pasta de destino exista. Se não, tenta criá-la.
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)
        # Cria um objeto BytesIO a partir dos bytes do ZIP para que zipfile possa lê-lo como um arquivo.
        in_memory_zip = io.BytesIO(zip_data)
        # Abre o ZIP em memória em modo de leitura ('r').
        with zipfile.ZipFile(in_memory_zip, 'r') as zipf:
            print(f"Extraindo arquivos para a pasta '{destination_folder}'...")
            # Extrai todo o conteúdo do ZIP para a pasta de destino especificada.
            zipf.extractall(destination_folder)
    except zipfile.BadZipFile:
        print("Erro: O arquivo de backup parece estar corrompido (não é um ZIP válido).", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Ocorreu um erro ao extrair os arquivos: {e}", file=sys.stderr)
        return False
    # Retorna True se a extração foi bem-sucedida.
    return True


# ROTINAS DE BACKUP E RESTAURAÇÃO
# Funções que orquestram o fluxo de interação com o usuário e as operações.

# Rotina completa para criar um novo backup seguro, guiando o usuário.
def perform_backup():
    print("\n--- Modo de Criação de Backup ---")

    source_path = input("Digite o caminho da pasta ou arquivo para fazer backup: ").strip()
    # Verifica se o caminho fornecido pelo usuário realmente existe no sistema.
    if not os.path.exists(source_path):
        print(f"Erro: O caminho de origem '{source_path}' não existe. Abortando.", file=sys.stderr)
        return

    output_name = input("Digite o nome base para o arquivo de backup (ex: backup_1): ").strip()
    # Garante que o nome do arquivo final sempre terá a extensão .enc.
    enc_filename = output_name + '.enc' if not output_name.endswith('.enc') else output_name

    dest_folder = input(f"Em qual pasta você gostaria de salvar '{enc_filename}'? (informe o caminho ou deixe em branco para salvar aqui): ").strip()

    # Verifica se o usuário especificou uma pasta de destino e se ela existe.
    if dest_folder and not os.path.isdir(dest_folder):
        try:
            # Tenta criar a pasta de destino se ela não existir.
            os.makedirs(dest_folder)
            print(f"Pasta de destino '{dest_folder}' criada.")
        except Exception as e:
            # Falha se não conseguir criar a pasta (ex: permissões insuficientes).
            print(f"Erro: Não foi possível criar a pasta de destino '{dest_folder}'.\nDetalhes: {e}", file=sys.stderr)
            return

    # Monta o caminho completo onde o arquivo .enc será salvo.
    # os.path.join lida corretamente com barras '/' e '\' entre sistemas.
    final_save_path = os.path.join(dest_folder, enc_filename)

    print("\nAVISO DE SEGURANÇA: Recomenda-se uma senha longa (mínimo 12 caracteres).")
    while True:
        # Usa getpass para solicitar a senha sem mostrá-la na tela (proteção contra shoulder surfing).
        password = getpass.getpass("Crie uma senha para o seu novo backup: ")
        # Validação básica de força da senha (comprimento mínimo).
        if len(password) < 12:
            print("AVISO: Senhas curtas são mais fáceis de quebrar. Por segurança, escolha uma senha mais longa.", file=sys.stderr)
            continue # Pede a senha novamente.
        password_confirm = getpass.getpass("Confirme a senha: ")
        if password == password_confirm:
            break # Senhas coincidem, pode prosseguir.
        else:
            print("As senhas não coincidem. Por favor, tente novamente.", file=sys.stderr)

    # Inicia as etapas técnicas do backup.
    print("\n[ETAPA 1 de 2] Compactando os dados...")
    zip_data = zip_source(source_path) # Chama a função de compactação.
    if not zip_data: # Verifica se a compactação falhou.
        print("❌ Falha na etapa de compressão. Abortando.", file=sys.stderr)
        return

    print("\n[ETAPA 2 de 2] Criptografando os dados...")
    try:
        # Gera o "Sal" aleatório usando uma fonte segura do sistema operacional.
        salt = os.urandom(SALT_SIZE)
        # Deriva a chave de criptografia a partir da senha e do "sal".
        key = derive_key(password, salt)
        # Cria uma instância do Fernet com a chave derivada.
        f = Fernet(key)
        # Criptografa os dados do ZIP que estavam na memória.
        # O resultado inclui os dados criptografados (AES) + a assinatura de integridade (HMAC).
        encrypted_data = f.encrypt(zip_data)

        # Abre o arquivo final em modo de escrita binária ('wb').
        with open(final_save_path, 'wb') as file:
            # Escreve o "Sal" no início do arquivo
            file.write(salt)
            # Escreve os dados criptografados (token Fernet) logo após o "sal"
            file.write(encrypted_data)

    except Exception as e:
        # Captura erros durante a derivação da chave ou criptografia
        print(f"Ocorreu um erro fatal durante a criptografia: {e}", file=sys.stderr)
        return

    # Mensagem final
    print("\n----------------------------------------")
    print("✅ Sucesso! Backup criptografado e protegido por senha criado em:")
    # mostrando o caminho completo do arquivo salvo
    print(f"   {os.path.abspath(final_save_path)}")
    print("\nLembre-se da sua senha! Sem ela, será impossível restaurar este backup.")
    print("----------------------------------------")


#Rotina completa para restaurar um backup existente, guiando o usuário
def perform_restore():
    print("\n--- Modo de Restauração de Backup ---")

    enc_file_path = input("Digite o caminho do arquivo de backup a ser restaurado (ex: C:\\Users\\SeuNome\\Documents\\backup.enc): ").strip()
    if not os.path.exists(enc_file_path):
        print(f"Erro: O arquivo '{enc_file_path}' não foi encontrado. Abortando.", file=sys.stderr)
        return

    password = getpass.getpass("Digite a senha para este backup: ")
    if not password:
        print("Erro: A senha não pode estar em branco. Abortando.", file=sys.stderr)
        return

    dest_folder = input("Onde você gostaria de salvar a pasta restaurada? (informe o caminho ou deixe em branco para salvar aqui): ").strip()
    if dest_folder and not os.path.isdir(dest_folder):
        try:
            os.makedirs(dest_folder)
            print(f"Pasta de destino '{dest_folder}' criada.")
        except Exception as e:
            print(f"Erro: Não foi possível criar a pasta de destino '{dest_folder}'.\nDetalhes: {e}", file=sys.stderr)
            return

    print("\n[ETAPA 1 de 2] Descriptografando o backup...")
    try:
        # Abre o arquivo .enc em modo de leitura binária ('rb')
        with open(enc_file_path, 'rb') as f:
            # Lê os primeiros SALT_SIZE bytes, que são o "sal"
            salt = f.read(SALT_SIZE)
            # Lê todo o restante do arquivo, que são os dados criptografados (token Fernet)
            encrypted_data = f.read()

        # Recria a chave usando a senha do usuário e o "sal" lido do arquivo
        key = derive_key(password, salt)
        f = Fernet(key)

        # Tenta descriptografar os dados. O método decrypt() do Fernet faz duas coisas:
        # 1. Verifica a assinatura de integridade (HMAC) usando a chave. Se falhar (dados corrompidos ou chave errada), levanta InvalidToken
        # 2. Se a integridade for válida, descriptografa os dados usando AES com a chave
        decrypted_data = f.decrypt(encrypted_data)

    except InvalidToken:
        print("❌ FALHA CRÍTICA: Senha incorreta ou arquivo corrompido! Acesso negado.", file=sys.stderr)
        return
    except Exception as e:
        print(f"Ocorreu um erro durante a descriptografia: {e}", file=sys.stderr)
        return

    # Se a descriptografia foi bem-sucedida, prossegue para a extração:
    print("\n[ETAPA 2 de 2] Extraindo os arquivos...")
    # Cria um nome para a pasta restaurada baseado no nome do arquivo .enc
    folder_name = os.path.splitext(os.path.basename(enc_file_path))[0] + "_restaurado"
    # Monta o caminho completo para a pasta de restauração
    final_restore_path = os.path.join(dest_folder, folder_name)

    # Chama a função para descompactar os dados (que agora estão em decrypted_data)
    if not unzip_data(decrypted_data, final_restore_path):
        print("❌ Falha na extração dos arquivos. Abortando.", file=sys.stderr)
        return

    # Mensagem final de sucesso:
    print("\n----------------------------------------")
    print("✅ Sucesso! Seus arquivos foram restaurados em:")
    print(f"   {os.path.abspath(final_restore_path)}")
    print("----------------------------------------")


#Função principal que exibe o menu e direciona o fluxo do programa
def main():
    logo = """
     ██████╗ ██╗      █████╗ ██╗   ██╗ ███████╗ ██╗   ██╗ ███╗   ███╗
    ██╔════╝ ██║     ██╔══██╗██║   ██║ ██╔════╝ ██║   ██║ ████╗ ████║
    ██║      ██║     ███████║██║   ██║ ███████╗ ██║   ██║ ██╔████╔██║
    ██║      ██║     ██╔══██║██║   ██║ ╚════██║ ██║   ██║ ██║╚██╔╝██║
    ╚██████╗ ███████╗██║  ██║╚██████╔╝ ███████║ ╚██████╔╝ ██║ ╚═╝ ██║
     ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚══════╝  ╚═════╝  ╚═╝     ╚═╝
    """
    print(logo)
    print("======================================================")
    print("      Bem-vindo ao Clausum - Seu Cofre Digital")
    print("======================================================")

    # Loop principal do menu. Continua até o usuário escolher sair.
    while True:
        print("\nEscolha uma opção:")
        print("  1. Criar um novo backup seguro")
        print("  2. Restaurar um backup existente")
        print("  3. Sair")
        choice = input("Opção: ").strip() # Pede a opção ao usuário.

        if choice == '1':
            perform_backup() # Chama a rotina de backup
        elif choice == '2':
            perform_restore() # hama a rotina de restauraçãoC
        elif choice == '3':
            print("Saindo do programa. Até logo!")
            break
        else:
            print("Opção inválida. Por favor, escolha 1, 2 ou 3.")


# Executa a função main() apenas quando o script é executado diretamente, e não quando importado
if __name__ == "__main__":
    main()
