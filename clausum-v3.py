#v3 - verificação de backup e de senha


import os
import stat
import zipfile
import sys
import io
import base64
import hashlib
import threading
from cryptography.fernet import Fernet, InvalidToken
import customtkinter as ctk
from tkinter import filedialog, messagebox
from zxcvbn import zxcvbn # biblioteca para medir força de senha


# ==============================================================================
# CONFIGURAÇÃO DO CUSTOMTKINTER
# ==============================================================================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# ==============================================================================
# CONSTANTES DE SEGURANÇA
# ==============================================================================
SALT_SIZE = 16
PBKDF2_ITERATIONS = 600_000


# ==============================================================================
# CONSTANTES DE INTERFACE
# ==============================================================================
ACCENT_COLOR = "#00BCD4"
SUCCESS_COLOR = "#2ECC71"
ERROR_COLOR = "#E74C3C"
WARNING_COLOR = "#F39C12"
# Cores para força de senha
STRENGTH_COLORS = {
    0: ERROR_COLOR,    # Muito Fraca
    1: ERROR_COLOR,    # Fraca
    2: WARNING_COLOR,  # Razoável
    3: SUCCESS_COLOR,  # Boa
    4: SUCCESS_COLOR   # Forte
}
STRENGTH_TEXT = {
    0: "Muito Fraca",
    1: "Fraca",
    2: "Razoável",
    3: "Boa",
    4: "Forte"
}


# ==============================================================================
# FUNÇÕES CRIPTOGRÁFICAS (BACKEND)
# ==============================================================================


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(kdf)


def zip_source(source_path, progress_callback=None):
    in_memory_zip = io.BytesIO()
    try:
        with zipfile.ZipFile(in_memory_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if os.path.isdir(source_path):
                files_list = []
                for root, _, files in os.walk(source_path):
                    for file in files:
                        files_list.append(os.path.join(root, file))
               
                total_files = len(files_list)
                for idx, file_path in enumerate(files_list):
                    archive_name = os.path.relpath(file_path, os.path.dirname(source_path))
                    zipf.write(file_path, arcname=archive_name)
                    if progress_callback:
                        progress_callback(int((idx + 1) / total_files * 50))
            elif os.path.isfile(source_path):
                archive_name = os.path.basename(source_path)
                zipf.write(source_path, arcname=archive_name)
                if progress_callback:
                    progress_callback(50)
            else:
                return None
    except Exception as e:
        print(f"Erro na compactação: {e}", file=sys.stderr)
        return None
   
    in_memory_zip.seek(0)
    return in_memory_zip.read()


def unzip_data(zip_data, destination_folder, progress_callback=None):
    try:
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)
       
        in_memory_zip = io.BytesIO(zip_data)
        with zipfile.ZipFile(in_memory_zip, 'r') as zipf:
            members = zipf.namelist()
            total_files = len(members)
            for idx, member in enumerate(members):
                zipf.extract(member, destination_folder)
                if progress_callback:
                    progress_callback(50 + int((idx + 1) / total_files * 50))
        return True
    except Exception as e:
        print(f"Erro na extração: {e}", file=sys.stderr)
        return False


# ==============================================================================
# INTERFACE GRÁFICA
# ==============================================================================


class ClausumGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Clausum - Seu Cofre Digital")
        self.root.geometry("800x920")
        self.root.resizable(False, False)
       
        # Variáveis
        self.source_path = ctk.StringVar()
        self.dest_path = ctk.StringVar()
        self.backup_name = ctk.StringVar()
        self.enc_file_path = ctk.StringVar()
        self.restore_dest_path = ctk.StringVar()
        self.verify_file_path = ctk.StringVar()
       
        self.create_widgets()
   
    def create_widgets(self):
        # Container principal com padding
        main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=40, pady=30)
       
        # ==============================================================================
        # CABEÇALHO
        # ==============================================================================
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.pack(pady=(0, 30))
       
        title_label = ctk.CTkLabel(
            header_frame,
            text="CLAUSUM",
            font=ctk.CTkFont(family="Courier New", size=42, weight="bold"),
            text_color=ACCENT_COLOR
        )
        title_label.pack()
       
        subtitle_label = ctk.CTkLabel(
            header_frame,
            text="Seu Cofre Digital Seguro",
            font=ctk.CTkFont(size=14),
            text_color="gray70"
        )
        subtitle_label.pack(pady=(5, 0))
       
        # ==============================================================================
        # SEGMENTED BUTTON (Tabs modernas)
        # ==============================================================================
        self.tab_var = ctk.StringVar(value="Criar Backup")
       
        segmented_button = ctk.CTkSegmentedButton(
            main_frame,
            values=["Criar Backup", "Restaurar Backup", "Verificar Backup"],
            command=self.tab_callback,
            variable=self.tab_var,
            font=ctk.CTkFont(size=14, weight="bold"),
            height=45
        )
        segmented_button.pack(pady=(0, 25))
        # definir o estado visual inicial
        segmented_button.set("Criar Backup") 
       
        # ==============================================================================
        # CONTAINER DE CONTEÚDO
        # ==============================================================================
        self.content_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True)
       
        # Criar ambas as views
        self.create_encrypt_view()
        self.create_restore_view()
        self.create_verify_view()
       
        # Mostrar view inicial
        self.show_encrypt_view()
        
   
    def tab_callback(self, value):
        if value == "Criar Backup":
            self.show_encrypt_view()
        elif value == "Restaurar Backup":
            self.show_restore_view()
        else: # Verificar Backup
            self.show_verify_view()
   
    def show_encrypt_view(self):
        self.restore_frame.pack_forget()
        self.verify_frame.pack_forget() # Esconde a view de verificação
        self.encrypt_frame.pack(fill="both", expand=True)
   
    def show_restore_view(self):
        """Esconde as outras abas e exibe a aba de restauração."""
        self.encrypt_frame.pack_forget()
        self.verify_frame.pack_forget() # Certifique-se de esconder a aba de verificação também
        self.restore_frame.pack(fill="both", expand=True)
   
    def show_verify_view(self):
        self.encrypt_frame.pack_forget()
        self.restore_frame.pack_forget()
        self.verify_frame.pack(fill="both", expand=True)
    
    def _clear_encrypt_fields(self):
        self.source_path.set("")
        self.dest_path.set("")
        self.backup_name.set("")
        # Limpa e reconfigura o show para password1_entry
        self.password1_entry.delete(0, 'end')
        self.password1_entry.configure(show="●")
        # Limpa e reconfigura o show para password2_entry
        self.password2_entry.delete(0, 'end')
        self.password2_entry.configure(show="●")
        # Resetar medidor de senha
        if hasattr(self, 'password_strength_bar'): # Verifica se existe
            self.update_password_strength()
        # Esconder/Resetar progresso
        self.encrypt_progress.set(0)
        self.encrypt_status.configure(text="")
        self.encrypt_progress.grid_forget()
        self.encrypt_status.grid_forget()

    def _clear_restore_fields(self):
        # Limpa os campos de caminho
        self.enc_file_path.set("")      
        self.restore_dest_path.set("")    
        # Limpa e reconfigura o show para restore_password_entry
        self.restore_password_entry.delete(0, 'end')
        self.restore_password_entry.configure(show="●")
        # Esconder/Resetar progresso
        self.restore_progress.set(0)
        self.restore_status.configure(text="")
        self.restore_progress.grid_forget()
        self.restore_status.grid_forget()

    def _clear_verify_fields(self):
        # Limpa o campo de caminho
        self.verify_file_path.set("")    
        # Limpa e reconfigura o show para verify_password_entry
        self.verify_password_entry.delete(0, 'end')
        self.verify_password_entry.configure(show="●")
        # Esconder/Resetar progresso
        self.verify_progress.set(0)
        self.verify_status.configure(text="")
        self.verify_progress.grid_forget()
        self.verify_status.grid_forget()

    # ==============================================================================
    # VIEW: CRIAR BACKUP
    # ==============================================================================
    def create_encrypt_view(self):
        self.encrypt_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")

        # DEBUG: Verificando o valor LOGO APÓS a criação
        print(f"DEBUG INICIAL: Valor de self.encrypt_frame = {self.encrypt_frame}")
        print(f"DEBUG INICIAL: Tipo de self.encrypt_frame = {type(self.encrypt_frame)}")
    
        # Grid configuration para melhor controle
        self.encrypt_frame.grid_columnconfigure(0, weight=1)
       
        row = 0
       
        # ETAPA 1: Seleção de Origem
        step1_label = ctk.CTkLabel(
            self.encrypt_frame,
            text="① Selecione o que deseja proteger",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        step1_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1
       
        source_container = ctk.CTkFrame(self.encrypt_frame)
        source_container.grid(row=row, column=0, sticky="ew", pady=(0, 25))
        source_container.grid_columnconfigure(0, weight=1)
       
        self.source_entry = ctk.CTkEntry(
            source_container,
            textvariable=self.source_path,
            placeholder_text="Nenhum arquivo ou pasta selecionado",
            height=40,
            font=ctk.CTkFont(size=13),
            state="disabled"
        )
        self.source_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")
       
        source_btn = ctk.CTkButton(
            source_container,
            text="📁 Selecionar",
            width=140,
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.select_source
        )
        source_btn.grid(row=0, column=1)
        row += 1
       
        # ETAPA 2: Nome e Destino
        step2_label = ctk.CTkLabel(
            self.encrypt_frame,
            text="② Configure o backup",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        step2_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1
       
        # Nome
        name_label = ctk.CTkLabel(
            self.encrypt_frame,
            text="Nome do Backup:",
            font=ctk.CTkFont(size=13),
            anchor="w"
        )
        name_label.grid(row=row, column=0, sticky="w", pady=(0, 5))
        row += 1
       
        self.backup_name_entry = ctk.CTkEntry(
            self.encrypt_frame,
            textvariable=self.backup_name,
            placeholder_text="Ex: documentos_importantes",
            height=40,
            font=ctk.CTkFont(size=13)
        )
        self.backup_name_entry.grid(row=row, column=0, sticky="ew", pady=(0, 15))
        row += 1
       
        # Destino
        dest_label = ctk.CTkLabel(
            self.encrypt_frame,
            text="Salvar em:",
            font=ctk.CTkFont(size=13),
            anchor="w"
        )
        dest_label.grid(row=row, column=0, sticky="w", pady=(0, 5))
        row += 1
       
        dest_container = ctk.CTkFrame(self.encrypt_frame)
        dest_container.grid(row=row, column=0, sticky="ew", pady=(0, 25))
        dest_container.grid_columnconfigure(0, weight=1)
       
        self.dest_entry = ctk.CTkEntry(
            dest_container,
            textvariable=self.dest_path,
            placeholder_text="Escolha onde salvar o backup criptografado",
            height=40,
            font=ctk.CTkFont(size=13),
            state="disabled"
        )
        self.dest_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")
       
        dest_btn = ctk.CTkButton(
            dest_container,
            text="📂 Escolher",
            width=140,
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.select_dest_encrypt
        )
        dest_btn.grid(row=0, column=1)
        row += 1
       
        # ETAPA 3: Senha (com Medidor de Força)
        step3_label = ctk.CTkLabel(
            self.encrypt_frame,
            text="③ Crie uma senha forte",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        step3_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1

        password_info = ctk.CTkLabel(
            self.encrypt_frame,
            text="⚠️ Use no mínimo 12 caracteres. Esta senha será necessária para restaurar o backup e não pode ser recuperada.",
            font=ctk.CTkFont(size=12),
            text_color=WARNING_COLOR,
            anchor="w",
            wraplength=650 # Garante que o texto quebre a linha se a janela for estreita
        )
        password_info.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1

        self.password1_entry = ctk.CTkEntry(
            self.encrypt_frame,
            placeholder_text="Digite sua senha (mínimo 12 caracteres)",
            height=40,
            font=ctk.CTkFont(size=13),
            show="●"
        )
        self.password1_entry.grid(row=row, column=0, sticky="ew", pady=(0, 5)) # Diminuído pady inferior
        # V V V V V V V V V V V V V V V V V V V V V V V V V V V V V V
        # Vincula o evento de soltar tecla à função de atualização
        self.password1_entry.bind("<KeyRelease>", self.update_password_strength)
        # ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^
        row += 1

        # --- Medidor de Força da Senha ---
        self.password_strength_bar = ctk.CTkProgressBar(
            self.encrypt_frame,
            height=6,
            mode="determinate"
        )
        self.password_strength_bar.set(0) # Começa vazio
        self.password_strength_bar.grid(row=row, column=0, sticky="ew", pady=(0, 5))
        row += 1

        self.password_strength_label = ctk.CTkLabel(
            self.encrypt_frame,
            text="Força da Senha: -",
            font=ctk.CTkFont(size=11),
            text_color="gray70", # Cor inicial neutra
            anchor="w"
        )
        self.password_strength_label.grid(row=row, column=0, sticky="w", pady=(0, 15)) # Aumentado pady inferior
        row += 1
        # --- Fim do Medidor ---

        # Campo Confirmar Senha (Sem label extra)
        self.password2_entry = ctk.CTkEntry(
            self.encrypt_frame,
            placeholder_text="Confirme sua senha",
            height=40,
            font=ctk.CTkFont(size=13),
            show="●"
        )
        self.password2_entry.grid(row=row, column=0, sticky="ew", pady=(0, 25)) # Espaçamento antes do botão
        row += 1

        # Botão Principal
        # (Removi os prints de debug daqui)
        self.encrypt_btn = ctk.CTkButton(
            self.encrypt_frame,
            text="🔒 CRIPTOGRAFAR E PROTEGER",
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=ACCENT_COLOR,
            hover_color="#008BA3",
            command=self.perform_encrypt
        )
        self.encrypt_btn.grid(row=row, column=0, sticky="ew", pady=(0, 20))
        row += 1

        # Progresso (inicialmente escondido, não precisa do .grid() aqui)
        self.encrypt_progress = ctk.CTkProgressBar(self.encrypt_frame, height=8, mode="determinate")
        self.encrypt_progress.set(0)
        self.encrypt_status = ctk.CTkLabel(self.encrypt_frame, text="", font=ctk.CTkFont(size=13), text_color="gray70")
   
    def update_password_strength(self, event=None):
        """Callback para atualizar o medidor de força da senha em tempo real."""
        password = self.password1_entry.get()
        if not password:
            self.password_strength_bar.set(0)
            self.password_strength_label.configure(text="Força da Senha: -", text_color="gray70")
            return


        results = zxcvbn(password)
        score = results['score'] # Score de 0 a 4


        # Atualiza a barra de progresso
        progress_value = (score + 1) / 5.0 # Mapeia 0-4 para 0.2-1.0
        self.password_strength_bar.set(progress_value)
        self.password_strength_bar.configure(progress_color=STRENGTH_COLORS[score])


        # Atualiza o texto e a cor do label
        self.password_strength_label.configure(
            text=f"Força da Senha: {STRENGTH_TEXT[score]}",
            text_color=STRENGTH_COLORS[score]
        )
   
    # ==============================================================================
    # VIEW: RESTAURAR BACKUP
    # ==============================================================================
    def create_restore_view(self):
        self.restore_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.restore_frame.grid_columnconfigure(0, weight=1)
        row = 0
       
        # ETAPA 1: Selecionar arquivo
        step1_label = ctk.CTkLabel(
            self.restore_frame,
            text="① Selecione o backup criptografado",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        step1_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1
       
        enc_container = ctk.CTkFrame(self.restore_frame)
        enc_container.grid(row=row, column=0, sticky="ew", pady=(0, 25))
        enc_container.grid_columnconfigure(0, weight=1)
       
        self.enc_entry = ctk.CTkEntry(
            enc_container,
            textvariable=self.enc_file_path,
            placeholder_text="Nenhum arquivo .enc selecionado",
            height=40,
            font=ctk.CTkFont(size=13),
            state="disabled"
        )
        self.enc_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")
       
        enc_btn = ctk.CTkButton(
            enc_container,
            text="📄 Selecionar .enc",
            width=160,
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.select_enc_file
        )
        enc_btn.grid(row=0, column=1)
        row += 1
       
        # ETAPA 2: Destino
        step2_label = ctk.CTkLabel(
            self.restore_frame,
            text="② Escolha onde restaurar",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        step2_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1
       
        restore_dest_container = ctk.CTkFrame(self.restore_frame)
        restore_dest_container.grid(row=row, column=0, sticky="ew", pady=(0, 25))
        restore_dest_container.grid_columnconfigure(0, weight=1)
       
        self.restore_dest_entry = ctk.CTkEntry(
            restore_dest_container,
            textvariable=self.restore_dest_path,
            placeholder_text="Pasta onde os arquivos serão restaurados",
            height=40,
            font=ctk.CTkFont(size=13),
            state="disabled"
        )
        self.restore_dest_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")
       
        restore_dest_btn = ctk.CTkButton(
            restore_dest_container,
            text="📂 Escolher",
            width=140,
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.select_dest_restore
        )
        restore_dest_btn.grid(row=0, column=1)
        row += 1
       
        # ETAPA 3: Senha
        step3_label = ctk.CTkLabel(
            self.restore_frame,
            text="③ Digite a senha do backup",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        step3_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1
       
        self.restore_password_entry = ctk.CTkEntry(
            self.restore_frame,
            placeholder_text="Senha do backup",
            height=40,
            font=ctk.CTkFont(size=13),
            show="●"
        )
        self.restore_password_entry.grid(row=row, column=0, sticky="ew", pady=(0, 25))
        row += 1
       
        # Botão Principal
        self.restore_btn = ctk.CTkButton(self.restore_frame, text="🔓 DESCRIPTOGRAFAR E RESTAURAR", height=50, font=ctk.CTkFont(size=16, weight="bold"), fg_color=ACCENT_COLOR, hover_color="#008BA3", command=self.perform_restore)
        self.restore_btn.grid(row=row, column=0, sticky="ew", pady=(0, 20))
        row += 1


        # Progresso (inicialmente escondido)
        self.restore_progress = ctk.CTkProgressBar(self.restore_frame, height=8, mode="determinate")
        self.restore_progress.set(0)
        self.restore_status = ctk.CTkLabel(self.restore_frame, text="", font=ctk.CTkFont(size=13), text_color="gray70")
   
    # ==============================================================================
    # VIEW: VERIFICAR BACKUP (NOVA)
    # ==============================================================================
    def create_verify_view(self):
        self.verify_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.verify_frame.grid_columnconfigure(0, weight=1)
        row = 0


        # ETAPA 1: Selecionar arquivo
        step1_label = ctk.CTkLabel(self.verify_frame, text="① Selecione o backup para verificar", font=ctk.CTkFont(size=16, weight="bold"), anchor="w")
        step1_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1


        verify_container = ctk.CTkFrame(self.verify_frame)
        verify_container.grid(row=row, column=0, sticky="ew", pady=(0, 25))
        verify_container.grid_columnconfigure(0, weight=1)


        self.verify_entry = ctk.CTkEntry(
            verify_container,
            textvariable=self.verify_file_path, # Usa a nova variável
            placeholder_text="Nenhum arquivo .enc selecionado",
            height=40,
            font=ctk.CTkFont(size=13),
            state="disabled"
        )
        self.verify_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")


        verify_btn_select = ctk.CTkButton(
            verify_container,
            text="📄 Selecionar .enc",
            width=160,
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.select_verify_file # Nova função de seleção
        )
        verify_btn_select.grid(row=0, column=1)
        row += 1


        # ETAPA 2: Senha
        step2_label = ctk.CTkLabel(self.verify_frame, text="② Digite a senha do backup", font=ctk.CTkFont(size=16, weight="bold"), anchor="w")
        step2_label.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1


        self.verify_password_entry = ctk.CTkEntry(
            self.verify_frame,
            placeholder_text="Senha do backup",
            height=40,
            font=ctk.CTkFont(size=13),
            show="●"
        )
        self.verify_password_entry.grid(row=row, column=0, sticky="ew", pady=(0, 25))
        row += 1


        # Botão Principal
        self.verify_btn = ctk.CTkButton(
            self.verify_frame,
            text="🔍 VERIFICAR INTEGRIDADE E SENHA",
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=ACCENT_COLOR,
            hover_color="#008BA3",
            command=self.perform_verify # Nova função de ação
        )
        self.verify_btn.grid(row=row, column=0, sticky="ew", pady=(0, 20))
        row += 1


        # Progresso (inicialmente escondido)
        self.verify_progress = ctk.CTkProgressBar(self.verify_frame, height=8, mode="determinate")
        self.verify_progress.set(0)
        self.verify_status = ctk.CTkLabel(self.verify_frame, text="", font=ctk.CTkFont(size=13), text_color="gray70")
   
    # ==============================================================================
    # CALLBACKS DE SELEÇÃO
    # ==============================================================================
    def select_source(self):
        path = filedialog.askdirectory(title="Selecione uma pasta")
        if not path:
            path = filedialog.askopenfilename(title="Ou selecione um arquivo")
        if path:
            self.source_path.set(path)
            if not self.backup_name.get():
                name = os.path.basename(path) + "_backup"
                self.backup_name.set(name)
   
    def select_dest_encrypt(self):
        path = filedialog.askdirectory(title="Onde salvar o backup?")
        if path:
            self.dest_path.set(path)
   
    def select_enc_file(self): # Usado na Restauração
        path = filedialog.askopenfilename(
            title="Selecione o arquivo de backup para restaurar",
            filetypes=[("Arquivos Clausum", "*.enc"), ("Todos os arquivos", "*.*")]
        )
        if path:
            self.enc_file_path.set(path)
   
    def select_verify_file(self):
        path = filedialog.askopenfilename(
            title="Selecione o arquivo de backup para verificar",
            filetypes=[("Arquivos Clausum", "*.enc"), ("Todos os arquivos", "*.*")]
        )
        if path:
            self.verify_file_path.set(path)
   
    def select_dest_restore(self):
        path = filedialog.askdirectory(title="Onde restaurar os arquivos?")
        if path:
            self.restore_dest_path.set(path)
   
    # ==============================================================================
    # OPERAÇÕES CRIPTOGRÁFICAS
    # ==============================================================================
    def perform_encrypt(self):
        if not self.source_path.get(): messagebox.showerror("Erro", "Selecione um arquivo ou pasta para backup!"); return
        if not self.backup_name.get(): messagebox.showerror("Erro", "Digite um nome para o backup!"); return
        if not self.dest_path.get(): messagebox.showerror("Erro", "Escolha onde salvar o backup!"); return
        password = self.password1_entry.get()
        if len(password) < 12: messagebox.showwarning("Senha Fraca", "A senha deve ter no mínimo 12 caracteres!"); return
        if password != self.password2_entry.get(): messagebox.showerror("Erro", "As senhas não coincidem!"); return


        # Mostra widgets de progresso antes de iniciar a thread
        self.encrypt_progress.grid(row=100, column=0, sticky="ew", pady=(0, 5))
        self.encrypt_status.grid(row=101, column=0, sticky="w")
        threading.Thread(target=self._encrypt_thread, args=(password,), daemon=True).start()
   
    def _encrypt_thread(self, password):
        self.root.after(0, lambda: self.encrypt_btn.configure(state="disabled", text="Processando..."))
        self.root.after(0, lambda: self.encrypt_progress.set(0))
        self.root.after(0, lambda: self.encrypt_status.configure(text="Iniciando...", text_color="gray70"))


        final_path = "" # Para usar na mensagem final
        try:
            # Compactar
            self.root.after(0, lambda: self.encrypt_status.configure(text="📦 Compactando arquivos..."))
            zip_data = zip_source(
                self.source_path.get(),
                lambda p: self.root.after(0, lambda: self.encrypt_progress.set(p / 100.0)) # Progresso 0-50%
            )
            if not zip_data: raise Exception("Falha na compactação")


            # Criptografar
            self.root.after(0, lambda: self.encrypt_status.configure(text="🔐 Criptografando dados..."))
            self.root.after(0, lambda: self.encrypt_progress.set(0.75)) # Marca progresso fixo
            salt = os.urandom(SALT_SIZE)
            key = derive_key(password, salt)
            f = Fernet(key)
            encrypted_data = f.encrypt(zip_data)


            # Salvar
            self.root.after(0, lambda: self.encrypt_status.configure(text="💾 Salvando arquivo protegido..."))
            self.root.after(0, lambda: self.encrypt_progress.set(0.90)) # Marca progresso fixo
            filename = self.backup_name.get()
            if not filename.endswith('.enc'): filename += '.enc'
            final_path = os.path.join(self.dest_path.get(), filename)
            # Escreve o arquivo .enc
            with open(final_path, 'wb') as file:
                file.write(salt)
                file.write(encrypted_data)

            # Tenta definir o arquivo como somente leitura após a criação
            try:
                # Pega as permissões atuais
                current_permissions = stat.S_IMODE(os.stat(final_path).st_mode)
                # Define como somente leitura para o dono (Windows geralmente usa isso)
                # Para maior compatibilidade, poderia ser stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH
                os.chmod(final_path, stat.S_IREAD)
                # Imprime no console (opcional, bom para debug)
                print(f"INFO: Atributo 'Somente Leitura' definido para {final_path}")
            except Exception as chmod_err:
                # Apenas avisa se não conseguir, não interrompe o fluxo
                print(f"AVISO: Não foi possível definir o atributo 'Somente Leitura'. {chmod_err}", file=sys.stderr)
                self.root.after(0, lambda: messagebox.showwarning("Aviso", "Não foi possível definir o atributo 'Somente Leitura' no arquivo de backup."))


            # Sucesso
            self.root.after(0, lambda: self.encrypt_progress.set(1.0))
            self.root.after(0, lambda: self.encrypt_status.configure(text="✅ Backup criado com sucesso!", text_color=SUCCESS_COLOR))
            self.root.after(0, lambda: messagebox.showinfo("Sucesso!", f"Backup criptografado criado:\n\n{final_path}\n\n⚠️ Guarde sua senha em local seguro!"))


        except Exception as e:
            self.root.after(0, lambda: self.encrypt_status.configure(text=f"❌ Erro: {str(e)}", text_color=ERROR_COLOR))
            self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha ao criar backup:\n{str(e)}"))
            # Limpa apenas senhas em caso de erro
            self.root.after(0, lambda: self.password1_entry.delete(0, 'end'))
            self.root.after(0, lambda: self.password2_entry.delete(0, 'end'))


        finally:
            # Reabilita botão e limpa campos de senha
            self.root.after(0, lambda: self.encrypt_btn.configure(state="normal", text="🔒 CRIPTOGRAFAR E PROTEGER"))
            self.root.after(0, lambda: self.password1_entry.delete(0, 'end'))
            self.root.after(0, lambda: self.password2_entry.delete(0, 'end'))
            self.root.after(0, self.update_password_strength) # Reseta medidor
            # Limpa todos os campos se foi sucesso (poderia ser dentro do try também)
            if final_path: # Verifica se a operação foi bem sucedida
                self.root.after(100, self._clear_encrypt_fields) # Delay pequeno para usuário ver msg

   
    def perform_restore(self):
        enc_file = self.enc_file_path.get()
        restore_dest = self.restore_dest_path.get()
        password = self.restore_password_entry.get()
        if not enc_file: messagebox.showerror("Erro", "Selecione um arquivo de backup!"); return
        if not restore_dest: messagebox.showerror("Erro", "Escolha onde restaurar os arquivos!"); return
        if not password: messagebox.showerror("Erro", "Digite a senha do backup!"); return

        # Mostra widgets de progresso
        self.restore_progress.grid(row=100, column=0, sticky="ew", pady=(0, 5))
        self.restore_status.grid(row=101, column=0, sticky="w")
        threading.Thread(target=self._restore_thread, args=(enc_file, restore_dest, password), daemon=True).start()
   
    def _restore_thread(self, enc_file, restore_dest, password):
        self.root.after(0, lambda: self.restore_btn.configure(state="disabled", text="Processando..."))
        self.root.after(0, lambda: self.restore_progress.set(0))
        self.root.after(0, lambda: self.restore_status.configure(text="Iniciando...", text_color="gray70"))


        final_path = "" # Para usar na mensagem final
        try:
            # Descriptografar
            self.root.after(0, lambda: self.restore_status.configure(text="🔓 Descriptografando backup..."))
            with open(enc_file, 'rb') as f:
                salt = f.read(SALT_SIZE)
                encrypted_data = f.read()
            self.root.after(0, lambda: self.restore_progress.set(0.25))
            key = derive_key(password, salt) # Pode demorar um pouco
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data) # Verifica HMAC aqui
            self.root.after(0, lambda: self.restore_progress.set(0.50))


            # Extrair
            self.root.after(0, lambda: self.restore_status.configure(text="📂 Extraindo arquivos..."))
            folder_name = os.path.splitext(os.path.basename(enc_file))[0] + "_restaurado"
            final_path = os.path.join(restore_dest, folder_name)
            if not unzip_data(
                decrypted_data,
                final_path,
                lambda p: self.root.after(0, lambda: self.restore_progress.set(p / 100.0)) # Progresso 50-100%
            ):
                raise Exception("Falha na extração")


            # Sucesso
            self.root.after(0, lambda: self.restore_progress.set(1.0))
            self.root.after(0, lambda: self.restore_status.configure(text="✅ Restauração concluída!", text_color=SUCCESS_COLOR))
            self.root.after(0, lambda: messagebox.showinfo("Sucesso!", f"Backup restaurado em:\n\n{final_path}"))


        except InvalidToken:
            self.root.after(0, lambda: self.restore_status.configure(text="❌ Senha incorreta ou arquivo corrompido!", text_color=ERROR_COLOR))
            self.root.after(0, lambda: messagebox.showerror("Erro", "Senha incorreta ou arquivo corrompido!"))
        except Exception as e:
            self.root.after(0, lambda: self.restore_status.configure(text=f"❌ Erro: {str(e)}", text_color=ERROR_COLOR))
            self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha ao restaurar:\n{str(e)}"))
            # Limpa apenas senhas em caso de erro
            self.root.after(0, lambda: self.password1_entry.delete(0, 'end'))
            self.root.after(0, lambda: self.password2_entry.delete(0, 'end'))


        finally:
            # Reabilita botão e limpa senha
            self.root.after(0, lambda: self.restore_btn.configure(state="normal", text="🔓 DESCRIPTOGRAFAR E RESTAURAR"))
            self.root.after(0, lambda: self.restore_password_entry.delete(0, 'end'))
            # Limpa todos os campos se foi sucesso (poderia ser dentro do try também)
            if final_path: # Verifica se a operação foi bem sucedida
                self.root.after(100, self._clear_encrypt_fields) # Delay pequeno para usuário ver msg

   
    def perform_verify(self):
        # Validações
        verify_file = self.verify_file_path.get()
        password = self.verify_password_entry.get()
        if not verify_file: messagebox.showerror("Erro", "Selecione um arquivo de backup para verificar!"); return
        if not password: messagebox.showerror("Erro", "Digite a senha do backup!"); return


        # Mostra widgets de progresso
        self.verify_progress.grid(row=100, column=0, sticky="ew", pady=(0, 5))
        self.verify_status.grid(row=101, column=0, sticky="w")
        threading.Thread(target=self._verify_thread, args=(verify_file, password), daemon=True).start()


    def _verify_thread(self, verify_file, password):
        # Desabilita botão e reseta progresso
        self.root.after(0, lambda: self.verify_btn.configure(state="disabled", text="Verificando..."))
        self.root.after(0, lambda: self.verify_progress.set(0))
        self.root.after(0, lambda: self.verify_status.configure(text="Iniciando verificação...", text_color="gray70"))

        success = False # Flag para saber se a operação deu certo
        try:
            # Ler arquivo e derivar chave
            self.root.after(0, lambda: self.verify_status.configure(text="🔑 Verificando senha e integridade..."))
            with open(verify_file, 'rb') as f:
                salt = f.read(SALT_SIZE)
                encrypted_data = f.read()
            self.root.after(0, lambda: self.verify_progress.set(0.25))
            key = derive_key(password, salt) # Pode demorar
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data) # Verifica HMAC aqui
            self.root.after(0, lambda: self.verify_progress.set(0.75))


            # Verificar integridade do ZIP interno
            self.root.after(0, lambda: self.verify_status.configure(text="📦 Verificando conteúdo do backup..."))
            try:
                in_memory_zip = io.BytesIO(decrypted_data)
                with zipfile.ZipFile(in_memory_zip, 'r') as zipf:
                    # testzip() retorna None se tudo ok, ou o nome do primeiro arquivo ruim
                    first_bad_file = zipf.testzip()
                    if first_bad_file is not None:
                        raise zipfile.BadZipFile(f"Arquivo corrompido dentro do backup: {first_bad_file}")
            except zipfile.BadZipFile as zip_err:
                raise Exception(f"Backup parece corrompido internamente: {str(zip_err)}") from zip_err


            # Sucesso
            self.root.after(0, lambda: self.verify_progress.set(1.0))
            self.root.after(0, lambda: self.verify_status.configure(text="✅ Verificação bem-sucedida! Senha correta e arquivo íntegro.", text_color=SUCCESS_COLOR))
            self.root.after(0, lambda: messagebox.showinfo("Sucesso!", "A verificação foi concluída.\nA senha está correta e o arquivo de backup parece estar íntegro."))


        except InvalidToken:
            self.root.after(0, lambda: self.verify_status.configure(text="❌ Senha incorreta ou arquivo corrompido!", text_color=ERROR_COLOR))
            self.root.after(0, lambda: messagebox.showerror("Falha na Verificação", "A senha está incorreta ou o arquivo de backup foi modificado/corrompido."))
        except Exception as e:
            self.root.after(0, lambda: self.verify_status.configure(text=f"❌ Erro na verificação: {str(e)}", text_color=ERROR_COLOR))
            self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha durante a verificação:\n{str(e)}"))
            # Limpa apenas senhas em caso de erro
            self.root.after(0, lambda: self.password1_entry.delete(0, 'end'))
            self.root.after(0, lambda: self.password2_entry.delete(0, 'end'))


        finally:
            # Reabilita botão e limpa senha
            self.root.after(0, lambda: self.verify_btn.configure(state="normal", text="🔍 VERIFICAR INTEGRIDADE E SENHA"))
            self.root.after(0, lambda: self.verify_password_entry.delete(0, 'end'))
            self.root.after(0, self._clear_encrypt_fields)
            if success:
                self.root.after(200, self._clear_restore_fields) # Chama a limpeza
            else: # Limpa só a senha se deu erro
                self.root.after(0, lambda: self.restore_password_entry.delete(0, 'end'))



# ==============================================================================
# MAIN
# ==============================================================================


if __name__ == "__main__":
    root = ctk.CTk()
    app = ClausumGUI(root)
    root.mainloop()
